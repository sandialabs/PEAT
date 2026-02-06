#!/usr/bin/env python3

import argparse
import sys
import timeit
from pathlib import Path
from pprint import pprint
from shutil import rmtree
from subprocess import run

OUT_DIR = Path.cwd() / "gen_peat_test_data_files"


class TestDataGenerator:
    input_paths = []  # type: list[str]
    input_globs = []  # type: list[str]
    input_filenames = []  # type: list[str]
    file_types = []  # type: list[str]
    dest_dir = ""  # type: str
    add_cli_args = ""  # type: str
    num_files_generated = 0  # type: int

    @classmethod
    def main(cls):
        for input_path in cls.input_paths:
            data_files = Path(input_path).resolve()
            assert data_files.is_dir()

            if cls.dest_dir:
                dest_dir = Path(cls.dest_dir).resolve()
            else:
                dest_dir = data_files
            assert dest_dir.is_dir()

            if cls.input_filenames:
                inputs = [Path(data_files, f).resolve() for f in cls.input_filenames]
            elif cls.input_globs:
                inputs = [file for glb_str in cls.input_globs for file in data_files.glob(glb_str)]
            else:
                inputs = [data_files]

            print(f"** Generating data from {len(inputs)} files **")
            pprint([in_file.name for in_file in inputs])

            for input_file in inputs:
                print(f"Generating data for {input_file}")
                start_time = timeit.default_timer()

                cls.gen_expected(input_file, dest_dir)

                duration = timeit.default_timer() - start_time
                print(f"Generated data in {duration:.2f} seconds")

            if OUT_DIR.exists():
                rmtree(OUT_DIR)

    @classmethod
    def gen_expected(cls, in_file: Path, dest_dir: Path):
        if OUT_DIR.exists():
            rmtree(OUT_DIR)

        cmd = (
            f"peat parse "
            f"-V --no-logo --no-color "
            f"-d {cls.__name__.replace('Generator', '').lower()} "
            f"-o {OUT_DIR.as_posix()} "
            f"{cls.add_cli_args} "
            f"-- {in_file.as_posix()}"
        )

        res = run(cmd, shell=True, capture_output=True, check=False)

        if not res.returncode == 0:
            print(
                f"Failed test gen for {in_file.name} (code: {res.returncode})",
                flush=True,
            )
            print(f"** stderr **\n\n{res.stderr.decode()}", flush=True)
            print(f"** stdout **\n\n{res.stdout.decode()}", flush=True)
            sys.exit(1)

        run_dir = sorted(OUT_DIR.glob("parse_*"))[0]
        res_dir = next(iter(Path(run_dir, "devices").iterdir()))

        for filetype in cls.file_types:
            src_files = list(res_dir.glob(filetype))

            if not src_files:
                print(f"WARNING: no output files for {filetype}")
                continue

            if len(src_files) > 1:
                print(f"WARNING: multiple output files for pattern {filetype}")
                continue

            dst = dest_dir / f"{in_file.name.split('.')[0]}_expected_{filetype}"

            # NOTE: workaround for windows (can't rename if file exists)
            if dst.exists():
                dst.unlink()

            # Move the file
            src_files[0].rename(dst)
            cls.num_files_generated += 1


class SELRelayGenerator(TestDataGenerator):
    input_paths = [
        "./tests/modules/sel/data_files/",
        "./tests/modules/sel/data_files/rdb/",
        "./tests/modules/sel/data_files/set_all/",
    ]
    input_globs = ["*.rdb", "*set_all.txt"]
    file_types = [
        "device-data-full.json",
        "device-data-summary.json",
        "extracted_SET_ALL.txt",
        "parsed-config.json",
        "raw-setall-configs.json",
    ]


class SELRTACGenerator(TestDataGenerator):
    input_paths = [
        "./tests/modules/sel/data_files/rtac/",
    ]
    input_filenames = [
        "SEL_RTAC",
        "accesspointrouter.tar.gz",
        "AccessPoints.tar.gz",
        "devices.tar.gz",
        "rtacexport3.tar.gz",
    ]
    file_types = [
        "device-data-full.json",
        "device-data-summary.json",
    ]


class SCEPTREGenerator(TestDataGenerator):
    input_paths = ["./tests/modules/sandia/data_files/"]
    input_globs = ["*.xml"]
    file_types = ["device-data-full.json", "device-data-summary.json"]


class IONGenerator(TestDataGenerator):
    input_paths = ["./tests/modules/schneider/ion/data_files/"]
    input_filenames = [
        "004.020.001_8650A.upg",
        "DEVINFO.DAT",
        "SITEINFO.DAT",
        "61850_log.txt",
    ]
    file_types = ["device-data-full.json", "device-data-summary.json"]


class M340Generator(TestDataGenerator):
    input_paths = ["./tests/modules/schneider/m340/data_files/"]
    input_globs = ["*.apx"]
    file_types = [
        "device-data-full.json",
        "device-data-summary.json",
        "parsed-config.json",
        "tc6.xml",
        "logic.st",
    ]


class SageGenerator(TestDataGenerator):
    input_paths = ["./tests/modules/schneider/sage/data_files/"]
    input_globs = ["*.tar.gz"]
    file_types = [
        "device-data-full.json",
        "device-data-summary.json",
        "parsed-config.json",
    ]


class GERelayGenerator(TestDataGenerator):
    input_paths = [
        "./tests/modules/ge/data_files/t60/",
        "./tests/modules/ge/data_files/l90/",
    ]
    file_types = [
        "device-data-full.json",
        "device-data-summary.json",
        "parsed-page-data.json",
        "processed-data.json",
    ]


class L5XGenerator(TestDataGenerator):
    input_paths = [
        "./examples/devices/l5x/",
        "./examples/devices/l5x/plc_rng/",
    ]
    input_globs = ["*.L5X"]
    file_types = ["device-data-full.json", "device-data-summary.json"]
    dest_dir = "./tests/modules/rockwell/data_files/"


class AwesomeToolGenerator(TestDataGenerator):
    input_paths = ["./examples/example_peat_module/"]
    input_filenames = ["awesome_output.json"]
    file_types = ["device-data-full.json", "device-data-summary.json"]
    dest_dir = "./examples/example_peat_module/"
    add_cli_args = "-I examples/example_peat_module/awesome_module.py"


class WindowsCEGenerator(TestDataGenerator):
    input_paths = [
        "./examples/devices/wince/tp700/",
        "./examples/devices/wince/panelview/",
    ]
    input_globs = ["*pillage-results.json"]
    file_types = ["device-data-full.json", "device-data-summary.json"]
    dest_dir = "./tests/modules/windows/data_files/"


def main():
    # dict: {"SELRTAC": SELRTACGenerator}
    generators: dict[str, type[TestDataGenerator]] = {
        k.split("Generator")[0]: v
        for k, v in globals().items()
        if isinstance(v, type) and issubclass(v, TestDataGenerator) and v is not TestDataGenerator
    }

    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument(
        "device_class",
        type=str,
        choices=[*generators.keys(), "all"],
    )

    args = arg_parser.parse_args()

    start_time = timeit.default_timer()
    files_generated = 0

    if args.device_class == "all":
        for generator in generators.values():
            generator.main()
            files_generated += generator.num_files_generated
    else:
        generators[args.device_class].main()
        files_generated += generators[args.device_class].num_files_generated

    duration = timeit.default_timer() - start_time
    print(f"Parsed {files_generated} files in {duration:.2f} seconds")


if __name__ == "__main__":
    main()
