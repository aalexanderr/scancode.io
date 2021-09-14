# SPDX-License-Identifier: Apache-2.0
#
# http://nexb.com and https://github.com/nexB/scancode.io
# The ScanCode.io software is licensed under the Apache License version 2.0.
# Data generated with ScanCode.io is provided as-is without warranties.
# ScanCode is a trademark of nexB Inc.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# Data Generated with ScanCode.io is provided on an "AS IS" BASIS, WITHOUT WARRANTIES
# OR CONDITIONS OF ANY KIND, either express or implied. No content created from
# ScanCode.io should be considered or used as legal advice. Consult an Attorney
# for any legal advice.
#
# ScanCode.io is a free software code scanning tool from nexB Inc. and others.
# Visit https://github.com/nexB/scancode.io for support and download.

from scanpipe.pipelines import Pipeline
from scanpipe.pipes.alpine import download_or_checkout_aports
from scanpipe.pipes.alpine import extract_summary_fields
from scanpipe.pipes.alpine import get_unscanned_packages_from_db
from scanpipe.pipes.alpine import prepare_scan_dir
from scanpipe.pipes.scancode import extract_archive, extract_archives
from scanpipe.pipes.scancode import run_scancode


class AlpinePackages(Pipeline):
    """
    A pipeline to complement missing alpine package data.
    Downloads and extracts needed information from aports repository and package source files.
    Alpine Linux does not provide copyrights and (in some cases) licenses for it's packages.
    """

    @classmethod
    def steps(cls):
        return (
            cls.create_alpine_versions_dict,
            cls.download_aports_repo,
            cls.complement_missing_package_data,
        )

    scancode_options = ["--copyright", "--license", "--summary"]

    def create_alpine_versions_dict(self):
        """
        Create a dict mapping alpine image ids from the database to alpine versions.
        """
        self.alpine_versions = {
            i["image_id"]: i["distro"]["version_id"]
            for i in self.project.extra_data["images"]
            if i["distro"]["identifier"] == "alpine"
        }

    def download_aports_repo(self):
        """
        Set pipeline's `aports_dir_path` variable to it's project temporary path.
        Iterate over every alpine version associated with this project.
        Download corresponding aports repository branches (alpine versions).
        """
        self.aports_dir_path = self.project.tmp_path
        for alpine_version in self.alpine_versions.values():
            download_or_checkout_aports(
                aports_dir_path=self.project.tmp_path, alpine_version=alpine_version
            )

    def complement_missing_package_data(self):
        """
        Iterate over alpine packages associated with this project.
        Checkout aports repository to the corresponding alpine version and a commit.
        Prepare scan target directory - download and extract package's sources.
        Run scancode and extract missing data (only copyrights for now).
        Update and save package's missing data to database.
        """
        for (
            alpine_version,
            aports_pkg_name,
            aports_commit_id,
            scan_target_path,
            scan_result_path,
            package,
        ) in get_unscanned_packages_from_db(
            project=self.project, alpine_versions=self.alpine_versions
        ):
            # self.log(f"package: {package.name}")
            # self.log(f"aports_dir_path {self.aports_dir_path} v: {alpine_version} c: {aports_commit_id}")
            # self.log(f"scan_target_path {scan_target_path} scan_result_path: {scan_result_path}")

            if scan_result_path.exists():
                package.update_extra_data(
                    data=extract_summary_fields(
                        scan_result_path=scan_result_path,
                        summary_field_names=["license_expressions", "copyrights"],
                    )
                )

            if not scan_result_path.exists():
                download_or_checkout_aports(
                    aports_dir_path=self.aports_dir_path,
                    alpine_version=alpine_version,
                    commit_id=aports_commit_id,
                )
                prepare_scan_dir(
                    package_name=aports_pkg_name, scan_target_path=scan_target_path
                )

                extract_errors = extract_archives(str(scan_target_path))
                if extract_errors:
                    # self.log(f"{extract_errors}")
                    self.add_error("\n".join(extract_errors))
                found_extracted = False
                for i in scan_target_path.iterdir():
                    if "-extract" in i.as_posix():
                        self.log(f"i with extract suffix{i}")
                        found_extracted = True
                        exitcode, output = run_scancode(
                            location=i.as_posix(),
                            output_file=scan_result_path.as_posix(),
                            options=self.scancode_options,
                        )
                        self.log(f"During scanning of {package.name}")
                        self.log(f"ScanCode-toolkit exited with {exitcode}, {output}")
                        self.add_error(f"{exitcode},{output}")
                        continue
                if not found_extracted:
                    self.log(
                        f"package {package.name} does not have anything to be scanned."
                    )
                    continue
            data = extract_summary_fields(
                scan_result_path,
                summary_field_names=["license_expressions", "copyrights"],
            )
            if aports_pkg_name is not package.name:
                data[
                    "Notices"
                ] = f"Please note that licenses and copyrights in extra_data pertain to whole {aports_pkg_name} codebase, not just a subset installed: {package.name}"
            package.update_extra_data(data)
