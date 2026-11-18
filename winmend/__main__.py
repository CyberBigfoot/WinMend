"""Launch with python -m winmend."""

import sys

if sys.argv[1:2] == ["--gpu-stress-worker"]:
    from winmend.features.gpu_stress import main
    raise SystemExit(main(sys.argv[2:]))
else:
    from winmend.bootstrap import main
    main()
