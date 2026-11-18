"""A bounded hardware OpenGL workload, run only in a disposable child process.

Qt's OpenGL wrappers keep this usable with the PySide6 already shipped by
WinMend. No downloaded benchmark, window, or extra Python package is needed.
"""

from __future__ import annotations

from array import array
import argparse
import json
import os
from pathlib import Path
import time


VERTEX_SHADER = """
attribute vec2 position;
void main() { gl_Position = vec4(position, 0.0, 1.0); }
"""

FRAGMENT_SHADER = """
uniform float phase;
void main() {
    vec2 p = gl_FragCoord.xy / vec2(1280.0, 720.0);
    float v = p.x + p.y + phase;
    for (int i = 0; i < 96; ++i) {
        v = sin(v * 1.731 + p.x * 0.17) + cos(v * 1.219 + p.y * 0.13);
    }
    gl_FragColor = vec4(0.5 + 0.5 * sin(v), 0.5 + 0.5 * cos(v), p.x, 1.0);
}
"""


def is_software_renderer(renderer):
    name = str(renderer).lower()
    return not name or any(token in name for token in (
        "llvmpipe", "softpipe", "software", "gdi generic", "swiftshader",
        "microsoft basic render",
    ))


def write_report(path, result):
    """The parent must never see a half-written progress/result record."""
    target = Path(path)
    staging = target.with_suffix(".tmp")
    staging.write_text(json.dumps(result), encoding="utf-8")
    os.replace(staging, target)


def run_workload(duration, report_path):
    # Keep Qt out of backend imports and initialise it on this child's main
    # thread, as QOffscreenSurface requires.
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QGuiApplication, QOffscreenSurface, QOpenGLContext, QSurfaceFormat
    from PySide6.QtOpenGL import QOpenGLBuffer, QOpenGLFramebufferObject, QOpenGLShader, QOpenGLShaderProgram

    QGuiApplication.setAttribute(Qt.AA_UseDesktopOpenGL)
    app = QGuiApplication(["WinMend GPU stress worker"])
    fmt = QSurfaceFormat()
    fmt.setVersion(2, 1)
    fmt.setSwapInterval(0)
    context = QOpenGLContext()
    context.setFormat(fmt)
    if not context.create():
        raise RuntimeError("A hardware OpenGL context could not be created.")
    surface = QOffscreenSurface()
    surface.setFormat(context.format())
    surface.create()
    if not surface.isValid() or not context.makeCurrent(surface):
        raise RuntimeError("A hardware rendering surface could not be created.")

    gl = context.functions()
    gl.initializeOpenGLFunctions()
    renderer = gl.glGetString(0x1F01)  # GL_RENDERER
    if is_software_renderer(renderer):
        raise RuntimeError(f"Software renderer ({renderer}); GPU load could not be verified.")

    # Resources must be destroyed while their owning context is current.
    program = QOpenGLShaderProgram()
    buffer = QOpenGLBuffer(QOpenGLBuffer.VertexBuffer)
    fbo = None
    try:
        if not program.addShaderFromSourceCode(QOpenGLShader.Vertex, VERTEX_SHADER):
            raise RuntimeError("GPU vertex shader failed: " + program.log())
        if not program.addShaderFromSourceCode(QOpenGLShader.Fragment, FRAGMENT_SHADER):
            raise RuntimeError("GPU fragment shader failed: " + program.log())
        if not program.link() or not program.bind():
            raise RuntimeError("GPU shader linking failed: " + program.log())
        # One oversized triangle covers the entire render target.
        vertices = array("f", [-1, -1, 3, -1, -1, 3]).tobytes()
        if not buffer.create() or not buffer.bind():
            raise RuntimeError("GPU vertex buffer allocation failed.")
        buffer.allocate(vertices, len(vertices))
        location = program.attributeLocation("position")
        phase = program.uniformLocation("phase")
        if location < 0 or phase < 0:
            raise RuntimeError("GPU shader inputs unavailable.")
        program.enableAttributeArray(location)
        program.setAttributeBuffer(location, 0x1406, 0, 2)  # GL_FLOAT
        fbo = QOpenGLFramebufferObject(1280, 720)
        if not fbo.isValid() or not fbo.bind():
            raise RuntimeError("GPU render target allocation failed.")
        gl.glViewport(0, 0, 1280, 720)
        result = {"state": "running", "renderer": renderer, "frames": 0, "elapsed": 0.0}
        write_report(report_path, result)
        started = time.monotonic()
        last_report = started
        frames = 0
        while time.monotonic() - started < duration:
            # Avoid PySide's scalar setUniformValue overload resolution: on
            # some versions a float selects an integer/colour overload.
            gl.glUniform1f(phase, float(frames % 1000) / 1000.0)
            gl.glDrawArrays(0x0004, 0, 3)  # GL_TRIANGLES
            gl.glFinish()  # Wait for actual GPU execution, rather than queuing CPU work.
            error = gl.glGetError()
            if error:
                raise RuntimeError(f"GPU rendering failed (OpenGL error 0x{error:04x}).")
            frames += 1
            if frames == 1:
                image = fbo.toImage()
                if image.isNull() or image.pixelColor(10, 10) == image.pixelColor(1260, 700):
                    raise RuntimeError("GPU render output could not be verified.")
                fbo.bind()
            now = time.monotonic()
            if now - last_report >= 1:
                result.update(frames=frames, elapsed=round(now - started, 3))
                write_report(report_path, result)
                app.processEvents()
                last_report = now
        if not frames:
            raise RuntimeError("No GPU frames were rendered.")
        result.update(state="done", frames=frames, elapsed=round(time.monotonic() - started, 3))
        write_report(report_path, result)
        return 0
    finally:
        if fbo is not None:
            fbo.release()
            del fbo
        buffer.destroy()
        program.removeAllShaders()
        del program
        context.doneCurrent()
        surface.destroy()


def main(argv=None):
    parser = argparse.ArgumentParser(description="WinMend internal GPU stress worker")
    parser.add_argument("--duration", type=float, default=60)
    parser.add_argument("--report", required=True)
    args = parser.parse_args(argv)
    if not 0 < args.duration <= 60:
        parser.error("duration must be greater than 0 and at most 60 seconds")
    try:
        return run_workload(args.duration, args.report)
    except Exception as exc:
        write_report(args.report, {"state": "failed", "error": str(exc)})
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
