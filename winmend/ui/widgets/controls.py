"""WinMend ui: widgets: controls."""

from __future__ import annotations

from PySide6.QtCore import (
    QEasingCurve,
    QEvent,
    QPersistentModelIndex,
    QRectF,
    QSize,
    QVariantAnimation,
    Qt as QtC,
    Signal,
)
from PySide6.QtGui import QColor, QIcon, QPainter, QPainterPath, QPalette, QPen, QPixmap
from PySide6.QtWidgets import (
    QCheckBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QStyle,
    QStyleOptionViewItem,
    QStyledItemDelegate,
    QVBoxLayout,
    QWidget,
)
import math


# ---------------------------------------------------------------- widgets ----

def wm_hline(T):
    f = QFrame()
    f.setFixedHeight(1)
    f.setStyleSheet(f"background:{T['border']};border:none;")
    return f


WM_SWITCH_WIDTH = 54


WM_SWITCH_HEIGHT = 24


WM_SWITCH_DURATION = 400


def _wm_paint_switch(painter, rect, position, enabled=True, focus_colour=None):
    """Native version of the red/green liquid switch from the supplied CSS."""
    position = max(0.0, min(1.0, position))
    off, on = QColor("#ff7a7a"), QColor("#85ff7a")
    track = QColor(*(round(a + (b - a) * position) for a, b in zip(
        (off.red(), off.green(), off.blue()), (on.red(), on.green(), on.blue()))))
    painter.save()
    painter.setRenderHint(QPainter.Antialiasing)
    if not enabled:
        painter.setOpacity(0.38)
    if focus_colour and enabled:
        painter.setPen(QPen(QColor(focus_colour), 1.5))
        painter.setBrush(QtC.NoBrush)
        painter.drawRoundedRect(rect.adjusted(-2, -2, 2, 2),
                                rect.height() / 2 + 2, rect.height() / 2 + 2)
    painter.setPen(QtC.NoPen)
    painter.setBrush(track)
    painter.drawRoundedRect(rect, rect.height() / 2, rect.height() / 2)
    padding = rect.height() / 12
    diameter = rect.height() - 2 * padding
    # Stretch and compress the knob during travel for the CSS's liquid feel.
    stretch = diameter * 0.28 * math.sin(math.pi * position)
    width, height = diameter + stretch, diameter - stretch * 0.35
    centre = rect.left() + padding + diameter / 2
    centre += (rect.width() - rect.height()) * position
    painter.setBrush(QColor("#000000"))
    painter.drawEllipse(QRectF(centre - width / 2, rect.center().y() - height / 2,
                              width, height))
    painter.restore()


class WMCheckBox(QCheckBox):
    """Animated slider with QCheckBox's selection signals and accessibility."""

    GAP = 9

    def __init__(self, text="", T=None, colour=None, parent=None):
        super().__init__(text, parent)
        self.T = T
        self._colour = colour
        self._position = 0.0
        self._target = False
        self._animation = QVariantAnimation(self)
        self._animation.setDuration(WM_SWITCH_DURATION)
        self._animation.setEasingCurve(QEasingCurve.InOutCubic)
        self._animation.valueChanged.connect(self._move_knob)
        self.toggled.connect(self._animate_to_state)
        self.setCursor(QtC.PointingHandCursor)
        self.setFocusPolicy(QtC.StrongFocus)
        self.setSizePolicy(QSizePolicy.Minimum, QSizePolicy.Fixed)

    def _move_knob(self, value):
        self._position = float(value)
        self.update()

    def _animate_to_state(self, checked):
        if self._target == checked:
            return
        self._target = checked
        self._animation.stop()
        target = float(checked)
        if not self.isVisible():
            self._move_knob(target)
            return
        self._animation.setStartValue(self._position)
        self._animation.setEndValue(target)
        self._animation.start()

    def setChecked(self, checked):
        super().setChecked(checked)
        # Programmatic selection resets often block signals.
        self._animate_to_state(self.isChecked())

    def setCheckState(self, state):
        super().setCheckState(state)
        self._animate_to_state(self.isChecked())

    def showEvent(self, event):
        self._animation.stop()
        self._target = self.isChecked()
        self._move_knob(float(self._target))
        super().showEvent(event)

    def hitButton(self, position):
        # Qt's default hit area still assumes a small square indicator.
        return self.rect().contains(position)

    def sizeHint(self):
        metrics = self.fontMetrics()
        width = WM_SWITCH_WIDTH + 4
        if self.text():
            width += self.GAP + metrics.horizontalAdvance(self.text())
        return QSize(width, max(WM_SWITCH_HEIGHT + 6, metrics.height() + 4))

    def minimumSizeHint(self):
        return self.sizeHint()

    def paintEvent(self, _event):
        T = self.T
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        enabled = self.isEnabled()
        top = (self.height() - WM_SWITCH_HEIGHT) / 2.0
        track = QRectF(2, top, WM_SWITCH_WIDTH, WM_SWITCH_HEIGHT)
        focus = (T['accent'] if T else self.palette().highlight().color().name())
        _wm_paint_switch(painter, track, self._position, enabled,
                         focus if self.hasFocus() else None)
        if self.text():
            colour = ((self._colour or T['text_2']) if enabled else T['text_3']) if T else (
                self.palette().color(QPalette.Active if enabled else QPalette.Disabled,
                                     QPalette.WindowText))
            painter.setPen(QColor(colour))
            painter.setFont(self.font())
            painter.drawText(self.rect().adjusted(WM_SWITCH_WIDTH + 4 + self.GAP, 0, 0, 0),
                             int(QtC.AlignLeft | QtC.AlignVCenter), self.text())


class WMSwitchDelegate(QStyledItemDelegate):
    """Paint checkable table options as sliders, retaining CheckStateRole."""

    def __init__(self, view):
        super().__init__(view)
        self.view = view
        self._positions = {}
        self._animations = {}
        placeholder = QPixmap(WM_SWITCH_WIDTH, WM_SWITCH_HEIGHT)
        placeholder.fill(QtC.transparent)
        self._placeholder = QIcon(placeholder)
        model = view.model()
        model.dataChanged.connect(self._data_changed)
        model.modelReset.connect(self._clear_animation)
        model.rowsAboutToBeRemoved.connect(self._clear_animation)

    def _clear_animation(self, *_args):
        for animation in self._animations.values():
            animation.stop()
            animation.deleteLater()
        self._animations.clear()
        self._positions.clear()

    def initStyleOption(self, option, index):
        super().initStyleOption(option, index)
        if index.data(QtC.CheckStateRole) is not None:
            # Let Qt reserve the slider's width and draw the row text normally.
            option.features &= ~QStyleOptionViewItem.HasCheckIndicator
            option.features |= QStyleOptionViewItem.HasDecoration
            option.icon = self._placeholder
            option.decorationSize = QSize(WM_SWITCH_WIDTH, WM_SWITCH_HEIGHT)

    def sizeHint(self, option, index):
        size = super().sizeHint(option, index)
        if index.data(QtC.CheckStateRole) is not None:
            size.setHeight(max(size.height(), WM_SWITCH_HEIGHT + 8))
        return size

    def paint(self, painter, option, index):
        super().paint(painter, option, index)
        state = index.data(QtC.CheckStateRole)
        if state is None:
            return
        styled = QStyleOptionViewItem(option)
        self.initStyleOption(styled, index)
        area = self.view.style().subElementRect(QStyle.SE_ItemViewItemDecoration,
                                               styled, self.view)
        rect = QRectF(QStyle.alignedRect(styled.direction, QtC.AlignCenter,
                                        QSize(WM_SWITCH_WIDTH, WM_SWITCH_HEIGHT), area))
        key = QPersistentModelIndex(index)
        position = self._positions.setdefault(key, float(state in (QtC.Checked, QtC.Checked.value)))
        enabled = self.view.isEnabled() and bool(index.flags() & QtC.ItemIsEnabled)
        focus = styled.palette.highlight().color().name() if (
            styled.state & QStyle.State_HasFocus) else None
        _wm_paint_switch(painter, rect, position, enabled, focus)

    def _data_changed(self, first, last, roles):
        if first.column() != 0 or (roles and QtC.CheckStateRole not in roles):
            return
        for row in range(first.row(), last.row() + 1):
            index = first.model().index(row, 0, first.parent())
            key = QPersistentModelIndex(index)
            state = index.data(QtC.CheckStateRole)
            if state is None or key not in self._positions:
                continue
            target = float(state in (QtC.Checked, QtC.Checked.value))
            old = self._animations.pop(key, None)
            if old:
                old.stop()
                old.deleteLater()
            if not self.view.isVisible():
                self._positions[key] = target
                continue
            if self._positions[key] == target:
                continue
            animation = QVariantAnimation(self)
            animation.setDuration(WM_SWITCH_DURATION)
            animation.setEasingCurve(QEasingCurve.InOutCubic)
            animation.setStartValue(self._positions[key])
            animation.setEndValue(target)
            animation.valueChanged.connect(lambda value, k=key: self._move_knob(k, value))
            animation.finished.connect(lambda k=key: self._finish_animation(k))
            self._animations[key] = animation
            animation.start()

    def _move_knob(self, key, value):
        self._positions[key] = float(value)
        self.view.viewport().update()

    def _finish_animation(self, key):
        animation = self._animations.pop(key, None)
        if animation:
            animation.deleteLater()

    def editorEvent(self, event, model, option, index):
        if (not self.view.isEnabled() or not index.flags() & QtC.ItemIsEnabled
                or not index.flags() & QtC.ItemIsUserCheckable):
            return False
        state = index.data(QtC.CheckStateRole)
        if state is None:
            return super().editorEvent(event, model, option, index)
        if event.type() in (QEvent.MouseButtonPress, QEvent.MouseButtonDblClick,
                            QEvent.MouseButtonRelease):
            if event.button() != QtC.LeftButton or not option.rect.contains(
                    event.position().toPoint()):
                return False
            if event.type() != QEvent.MouseButtonRelease:
                self.view.setCurrentIndex(index)
                return True
        elif event.type() == QEvent.KeyPress:
            if event.key() not in (QtC.Key_Space, QtC.Key_Select) or event.isAutoRepeat():
                return False
        else:
            return False
        return model.setData(index, QtC.Unchecked.value if state in (QtC.Checked, QtC.Checked.value)
                             else QtC.Checked.value, QtC.CheckStateRole)


class WMThemeSwitch(WMCheckBox):
    """Monochrome, two-knob theme switch inspired by the supplied CSS."""

    def __init__(self, T, parent=None):
        super().__init__(T=T, parent=parent)
        self._animation.setDuration(525)  # 300 ms travel plus the CSS's 225 ms delay
        self._animation.setEasingCurve(QEasingCurve.Linear)
        self.setFixedSize(self.sizeHint())
        self.setAccessibleName("Dark mode")
        self.setToolTip("Switch light/dark mode for this session. Startup follows Windows.")

    def sizeHint(self):
        return QSize(64, 36)

    def paintEvent(self, _event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        rect = QRectF(2, 3, 60, 30)
        if self.hasFocus():
            painter.setPen(QPen(QColor(self.T['accent']), 1.5))
            painter.setBrush(QtC.NoBrush)
            painter.drawRoundedRect(rect.adjusted(-2, -2, 2, 2), 17, 17)
        shade = round(26 + 204 * self._position)
        painter.setPen(QtC.NoPen)
        painter.setBrush(QColor(shade, shade, shade))
        painter.drawRoundedRect(rect, 15, 15)
        path = QPainterPath()
        path.addRoundedRect(rect, 15, 15)
        painter.setClipPath(path)
        painter.setBrush(QColor(256 - shade, 256 - shade, 256 - shade))
        if self._position in (0.0, 1.0):
            positions = [7 + 30 * self._position]
        else:
            elapsed = self._animation.currentTime()
            travel = min(1.0, elapsed / 300)
            travel = 1 - (1 - travel) ** 3
            delayed = max(0.0, min(1.0, (elapsed - 225) / 300))
            bounce = QEasingCurve(QEasingCurve.OutBack).valueForProgress(delayed)
            positions = ([7 + 60 * travel, -23 + 60 * bounce] if self._target
                         else [37 - 60 * travel, 67 - 60 * bounce])
        for x in positions:
            painter.drawEllipse(QRectF(x, 8, 20, 20))


class WMThemeCurtain(QWidget):
    """Reveal the new theme from left to right without rebuilding live pages."""

    finished = Signal()

    def __init__(self, parent, snapshot):
        super().__init__(parent)
        self._snapshot = snapshot
        self._progress = 0.0
        self.setGeometry(parent.rect())
        self.setAttribute(QtC.WA_TransparentForMouseEvents)
        self.setAttribute(QtC.WA_TranslucentBackground)
        self.setStyleSheet("background:transparent;")
        self.animation = QVariantAnimation(self)
        self.animation.setDuration(300)
        self.animation.setStartValue(0.0)
        self.animation.setEndValue(1.0)
        self.animation.setEasingCurve(QEasingCurve.OutCubic)
        self.animation.valueChanged.connect(self._advance)
        self.animation.finished.connect(self.finish)
        self.show()
        self.raise_()
        self.animation.start()

    def _advance(self, value):
        self._progress = float(value)
        self.update()

    def paintEvent(self, _event):
        painter = QPainter(self)
        left = self.width() * self._progress
        painter.setClipRect(QRectF(left, 0, self.width() - left, self.height()))
        painter.drawPixmap(self.rect(), self._snapshot)

    def finish(self):
        self.animation.stop()
        self.hide()
        self.finished.emit()
        self.deleteLater()


class WMPill(QLabel):
    """Small status chip: Admin / duration / risk."""

    def __init__(self, text, color):
        super().__init__(text)
        self.setStyleSheet(
            f"color:{color};background:transparent;border:1px solid {color};"
            f"border-radius:9px;padding:1px 8px;font-size:10px;font-weight:600;")
        self.setFixedHeight(19)


class WMTaskCard(QFrame):
    """One task: checkbox for batching, Run for one-offs."""

    def __init__(self, task, T, simple, on_run, on_toggle, checked=False):
        super().__init__()
        self.task = task
        self.setObjectName("card")
        self.setStyleSheet(f"""
            #card {{ background:{T['card']}; border:1px solid {T['border']};
                     border-radius:8px; }}
            #card:hover {{ background:{T['card_hi']}; border:1px solid {T['border_hi']}; }}
        """)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(15, 13, 13, 13)
        lay.setSpacing(13)

        self.cb = WMCheckBox(T=T)
        self.cb.setAccessibleName(task.display_title(simple))
        self.cb.setToolTip("Select this task to run it with the rest of your selection.")
        # Cards are rebuilt on every category/mode switch; restore the saved
        # selection BEFORE wiring the signal so construction never re-toggles it.
        self.cb.setChecked(checked)
        self.cb.toggled.connect(lambda c: on_toggle(task.id, c))
        lay.addWidget(self.cb, 0, QtC.AlignVCenter)

        mid = QVBoxLayout()
        mid.setSpacing(5)
        t = QLabel(task.display_title(simple))
        t.setStyleSheet(f"color:{T['text']};font-size:14px;font-weight:600;background:transparent;")
        mid.addWidget(t)
        d = QLabel(task.desc)
        d.setWordWrap(True)
        d.setStyleSheet(f"color:{T['text_3']};font-size:12px;background:transparent;")
        mid.addWidget(d)

        pills = QHBoxLayout()
        pills.setSpacing(6)
        if task.admin:
            pills.addWidget(WMPill("Admin", T['warn']))
        pills.addWidget(WMPill(task.duration_label(), T['text_3']))
        if task.reboot:
            pills.addWidget(WMPill("Restarts PC", T['danger']))
        elif task.reboot_after:
            # Restarts nothing itself; the run just ends by offering one.
            pills.addWidget(WMPill("Restart to finish", T['warn']))
        if task.risk == "destructive":
            pills.addWidget(WMPill("Removes software", T['danger']))
        elif task.risk == "safe":
            # only claimed when the task genuinely changes nothing
            pills.addWidget(WMPill("Read-only", T['ok']))
        if task.restore_point:
            pills.addWidget(WMPill("Restore point first", T['ok']))
        pills.addStretch()
        mid.addLayout(pills)
        lay.addLayout(mid, 1)

        run = QPushButton("Run")
        run.setCursor(QtC.PointingHandCursor)
        run.setFixedSize(72, 31)
        run.setStyleSheet(f"""
            QPushButton {{ background:transparent;color:{T['text_2']};
                border:1px solid {T['border_hi']};border-radius:6px;
                font-size:12px;font-weight:600; }}
            QPushButton:hover {{ background:{T['accent']};color:#fff;
                border:1px solid {T['accent']}; }}
        """)
        run.clicked.connect(lambda: on_run(task))
        lay.addWidget(run, 0, QtC.AlignVCenter)

    def matches(self, needle):
        t = self.task
        hay = f"{t.title} {t.plain or ''} {t.desc} {t.id}".lower()
        return needle in hay
