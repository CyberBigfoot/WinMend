"""WinMend entry point; historical imports remain available for integrations."""

if __name__ == "__main__":
    import sys
    if sys.argv[1:2] == ["--gpu-stress-worker"]:
        from winmend.features.gpu_stress import main
        raise SystemExit(main(sys.argv[2:]))
    else:
        from winmend.bootstrap import main
        main()
else:
    from winmend.compat import *  # Includes the historical private helper names.
