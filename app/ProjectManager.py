"""
LEGION (https://shanewilliamscott.com)
Copyright (c) 2025 Shane William Scott

    This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later
    version.

    This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
    warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
    details.

    You should have received a copy of the GNU General Public License along with this program.
    If not, see <http://www.gnu.org/licenses/>.

Author(s): Shane Scott (sscott@shanewilliamscott.com), Dmitriy Dubson (d.dubson@gmail.com)
"""

import ntpath
import os
import shutil
import sys
from typing import Tuple

from app.Project import Project, ProjectProperties
from app.tools.ToolCoordinator import fileExists
from app.auxiliary import Wordlist, getTempFolder
from app.shell.Shell import Shell
from app.tools.nmap.NmapPaths import getNmapRunningFolder
from db.RepositoryFactory import RepositoryFactory
from db.SqliteDbAdapter import Database, DatabaseIntegrityError
from sqlalchemy.exc import DatabaseError as SADatabaseError

tempDirectory = getTempFolder()


class ProjectManager:
    def __init__(self, shell: Shell, repositoryFactory: RepositoryFactory, logger):
        self.shell = shell
        self.repositoryFactory = repositoryFactory
        self.logger = logger

    def createNewProject(self, projectType: str, isTemp: bool) -> Project:
        database = self.__createDatabase()
        workingDirectory = self.shell.get_current_working_directory()

        # to store tool output of finished processes
        outputFolder = self.shell.create_temporary_directory(prefix="legion-", suffix="-tool-output",
                                                             directory=tempDirectory)

        # to store tool output of running processes
        runningFolder = self.shell.create_temporary_directory(
            prefix="legion-",
            suffix="-running",
            directory=tempDirectory
        )

        self.shell.create_directory_recursively(f"{outputFolder}/screenshots")  # to store screenshots
        self.shell.create_directory_recursively(getNmapRunningFolder(runningFolder))  # to store nmap output
        self.shell.create_directory_recursively(f"{runningFolder}/hydra")  # to store hydra output
        self.shell.create_directory_recursively(f"{runningFolder}/dnsmap")  # to store dnsmap output

        (usernameWordList, passwordWordList) = self.__createUsernameAndPasswordWordLists(outputFolder)
        repositoryContainer = self.repositoryFactory.buildRepositories(database)

        projectName = database.name
        projectProperties = ProjectProperties(
            projectName, workingDirectory, projectType, isTemp, outputFolder, runningFolder, usernameWordList,
            passwordWordList, storeWordListsOnExit=True
        )
        return Project(projectProperties, repositoryContainer, database)

    def openExistingProject(self, projectName: str, projectType: str = "legion") -> Project:
        self.logger.info(f"Opening existing project: {projectName}...")
        database = self.__createDatabase(projectName)
        try:
            database.verify_integrity()
        except DatabaseIntegrityError:
            database.dispose()
            raise
        workingDirectory = f"{ntpath.dirname(projectName)}/"
        outputFolder, _ = self.__determineOutputFolder(projectName, projectType)
        runningFolder = self.shell.create_temporary_directory(suffix="-running", prefix=projectType + '-',
                                                              directory=tempDirectory)
        (usernameWordList, passwordWordList) = self.__createUsernameAndPasswordWordLists(outputFolder)
        projectProperties = ProjectProperties(
            projectName=projectName, workingDirectory=workingDirectory, projectType=projectType, isTemporary=False,
            outputFolder=outputFolder, runningFolder=runningFolder, usernamesWordList=usernameWordList,
            passwordWordList=passwordWordList, storeWordListsOnExit=True
        )
        try:
            repositoryContainer = self.repositoryFactory.buildRepositories(database)
        except DatabaseIntegrityError:
            database.dispose()
            raise
        except SADatabaseError as exc:
            database.dispose()
            raise DatabaseIntegrityError(f"Failed to initialise repositories: {exc}") from exc
        return Project(projectProperties, repositoryContainer, database)

    def closeProject(self, project: Project) -> None:
        self.logger.info(f"Closing project {project.properties.projectName}...")
        # if current project is not temporary & delete wordlists if necessary
        projectProperties = project.properties
        try:
            if not projectProperties.isTemporary:
                if not projectProperties.storeWordListsOnExit:
                    self.logger.info('Removing wordlist files.')
                    self.shell.remove_file(projectProperties.usernamesWordList.filename)
                    self.shell.remove_file(projectProperties.passwordWordList.filename)
            else:
                self.logger.info('Removing temporary files and folders...')
                self.shell.remove_file(projectProperties.projectName)
                self.shell.remove_directory(projectProperties.outputFolder)

            self.logger.info('Removing running folder at close...')
            self.shell.remove_directory(projectProperties.runningFolder)
        except:
            self.logger.info('Something went wrong removing temporary files and folders..')
            self.logger.info("Unexpected error: {0}".format(sys.exc_info()[0]))

    # this function copies the current project files and folder to a new location
    # if the replace flag is set to 1, it overwrites the destination file and folder
    def saveProjectAs(self, project: Project, fileName: str, replace=0, projectType="legion") -> Project:
        self.logger.info(f"Saving project {project.properties.projectName}...")
        toolOutputFolder, normalizedFileName = self.__determineOutputFolder(fileName, projectType)
        source_project_name = str(project.properties.projectName or "")
        source_output_folder = str(project.properties.outputFolder or "")

        same_db_path = self._same_path(normalizedFileName, source_project_name)
        same_output_folder = self._same_path(toolOutputFolder, source_output_folder)
        if same_db_path and same_output_folder:
            self.logger.info("Save target matches current project path; skipping SaveAs copy/reopen.")
            return project

        # check if filename already exists (skip the check if we want to replace the file)
        if replace == 0 and fileExists(self.shell, normalizedFileName):
            self.logger.warning(f"File {normalizedFileName} already exists and replace flag not set; skipping save.")
            return project

        try:
            project.database.verify_integrity()
        except DatabaseIntegrityError as exc:
            self.logger.error(f"Aborting save: integrity check failed for {project.properties.projectName}: {exc}")
            raise

        # perform safe SQLite backup
        try:
            project.database.backup_to(normalizedFileName)
        except DatabaseIntegrityError as exc:
            self.logger.error(f"Failed to backup database to {normalizedFileName}: {exc}")
            raise

        # Ensure the copied database is readable before proceeding
        validation_db = None
        try:
            validation_db = Database(normalizedFileName)
            validation_db.verify_integrity()
        finally:
            if validation_db:
                validation_db.dispose()

        # copy tool output folder contents
        if same_output_folder:
            self.logger.info("Output folder already matches destination; skipping copy.")
        else:
            if os.path.exists(toolOutputFolder):
                if replace:
                    shutil.rmtree(toolOutputFolder, ignore_errors=True)
                else:
                    self.logger.info(f"Merging tool output into existing folder {toolOutputFolder}")
            shutil.copytree(project.properties.outputFolder, toolOutputFolder, dirs_exist_ok=True)

        if project.properties.isTemporary and not same_db_path:
            self.shell.remove_file(project.properties.projectName)
        if project.properties.isTemporary and not same_output_folder:
            self.shell.remove_directory(project.properties.outputFolder)

        self.logger.info(f"Project saved as {normalizedFileName}.")
        if same_db_path:
            return project
        return self.openExistingProject(normalizedFileName, projectType)

    @staticmethod
    def _same_path(path_a: str, path_b: str) -> bool:
        if not path_a or not path_b:
            return False
        try:
            return os.path.samefile(path_a, path_b)
        except Exception:
            a = os.path.normcase(os.path.realpath(str(path_a)))
            b = os.path.normcase(os.path.realpath(str(path_b)))
            return a == b

    def __createDatabase(self, projectName: str = None) -> Database:
        if projectName:
            return Database(projectName)

        databaseFile = self.shell.create_named_temporary_file(
            suffix=".legion",
            prefix="legion-",
            directory=tempDirectory,
            delete_on_close=False
        )  # to store the db file
        return Database(databaseFile.name)

    @staticmethod
    def setStoreWordListsOnExit(project: Project, storeWordListsOnExit: bool) -> None:
        projectProperties = ProjectProperties(
            projectName=project.properties.projectName, workingDirectory=project.properties.workingDirectory,
            projectType=project.properties.projectType, isTemporary=project.properties.isTemporary,
            outputFolder=project.properties.outputFolder, runningFolder=project.properties.runningFolder,
            usernamesWordList=project.properties.usernamesWordList,
            passwordWordList=project.properties.passwordWordList, storeWordListsOnExit=storeWordListsOnExit
        )
        project.properties = projectProperties

    @staticmethod
    def __determineOutputFolder(projectName: str, projectType: str) -> Tuple[str, str]:
        nameOffset = len(projectType) + 1
        if not projectName.endswith(projectType):
            # use the same name as the file for the folder (without the extension)
            return f"{projectName}-tool-output", f"{projectName}.{projectType}"
        else:
            return f"{projectName[:-nameOffset]}-tool-output", projectName

    @staticmethod
    def __createUsernameAndPasswordWordLists(outputFolder: str) -> Tuple[Wordlist, Wordlist]:
        usernamesWordlist = Wordlist(f"{outputFolder}/legion-usernames.txt")  # to store found usernames
        passwordWordlist = Wordlist(f"{outputFolder}/legion-passwords.txt")  # to store found passwords
        return usernamesWordlist, passwordWordlist
