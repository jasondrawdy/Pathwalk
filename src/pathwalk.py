# -*- coding: utf-8 -*-
# ########################################################################
# Program: Pathwalk
# Author: "Jason Drawdy (Buddha)"
# Version: "1.0.0"
# Date: 11/3/21 @ 3:00 AM
# #########################################################################
# main.py - Encapsulates all functions for generating a system map used for
# hash lookups in a multi-platform way including Windows, Linux, & macOS.
#
# Description:
# A compact module which can be utilized to generate a hash map including
# system files, directories, and all of their relevant information.
# #########################################################################
import os #? Allows us to access file system functions and variables.
import re #? Allos us to more easily identify patterns within data strings.
import sys #? Allows us to utilize system functions like exiting the program.
import getopt #? Allows us to determine and organize script variables/paramters.
import hashlib #? Allows us to generate a checksum for a file or binary data.
import platform #? Allows the use of Python specific functions such as current version.
import datetime #? Allows for timestamp generation used within the hash map file itself.
from typing import Union #? Allows for type annotation which enhances readability of code.

#? This is global information about the script/program itself.
_version = "1.0.0"
_version_name = "Pansophic"
_directory_log_path = f"./directories-{datetime.datetime.now().strftime('%Y-%m-%d')}.txt"
_hashmap_log_path = f"./hashmap-{datetime.datetime.now().strftime('%Y-%m-%d')}.txt"
_error_log_path = f"./maperrors-{datetime.datetime.now().strftime('%Y-%m-%d')}.txt"

def _get_timestamp() -> None:
    """Returns the current date and time in a formatted aesthetic for logging."""
    return f"[{datetime.datetime.now().strftime('%Y-%m-%d @ %H:%M:%S')}]: > "

def _log_error(logpath: str, message: str, print_to_console: bool = False) -> None:
    """Simple interal logging method for writing mapping errors to a log file.
    
    Parameters
    ----------
    :param logpath: The location of the log file on the system where scan results are written.
    :type logpath: str\n
    :param message: The actual data to write to the log file.
    :type message: str\n
    :param print_to_console: A flag which determines if results should be shown in the terminal.
    :type print_to_console: bool, optional
    """
    if print_to_console: print(message)
    with open(logpath, 'a') as log:
        log.write(f"{_get_timestamp()}{message}\n")

def _log_directory(logpath: str, message: str, print_to_console: bool = False) -> None:
    """Simple interal logging method for writing mapping system directories to a log file.
    
    Parameters
    ----------
    :param logpath: The location of the log file on the system where scan results are written.
    :type logpath: str\n
    :param message: The actual data to write to the log file.
    :type message: str\n
    :param print_to_console: A flag which determines if results should be shown in the terminal.
    :type print_to_console: bool, optional
    """
    if print_to_console: print(message)
    with open(logpath, 'a') as log:
        log.write(f"{_get_timestamp()}{message}\n")

class HashType():
    """A collection of common checksum generation algorithms."""
    MD5 = hashlib.md5
    SHA1 = hashlib.sha1
    SHA224 = hashlib.sha224
    SHA256 = hashlib.sha256
    SHA384 = hashlib.sha384
    SHA512 = hashlib.sha512

    @staticmethod
    def get_type(algorithm: str) -> object:
        """Determines which algorithm instance, if any, should be returned to be used for checksum operations.
        
        Parameters
        ----------
        :param algorithm: A string representation of the checksum algorithm coroutine.
        :type algorithm: str
        
        Returns
        -------
        :rtype: _Hash
        :return: A hashing coroutine determined from the provided algorithm.
        """
        algorithms = {
            "md5": HashType.MD5,
            "sha1": HashType.SHA1,
            "sha224": HashType.SHA224,
            "sha256": HashType.SHA256,
            "sha384": HashType.SHA384,
            "sha512": HashType.SHA512
        }
        algorithm = algorithms.get(algorithm.lower(), None)
        if algorithm is None:
            print(f"\"{algorithm}\" is not a supported algorithm. Currently only MD5, SHA1, SHA224, SHA256, SHA384, and SHA512 are supported")
        else: return algorithm

class Hashing():
    """A security class supporting simple data hashing and checksum operations."""
    @staticmethod
    def get_checksum(data: Union[str, bytes], algorithm: HashType) -> str:
        """Calculates a hash for a given message or data chunk given a valid algorithm.

        Parameters
        ----------
        :param data: The byte array used to calculate a checksum.
        :type data: bytes\n
        :param algorithm: A `HashType` coroutine to utilize for checksum calculations.
        :type algorithm: HashType

        Returns
        -------
        :rtype: str
        :return: The hexadecimal digest of the generated data checksum.
        """
        try:
            if callable(algorithm):
                if isinstance(data, str):
                    data = str.encode(data, "utf-8")
                checksum = algorithm()
                checksum.update(data)
                return checksum.hexdigest()
            else: print("Please provide a valid algorithm to generate a checksum. Currently only MD5, SHA1, SHA224, SHA256, SHA384, and SHA512 are supported.")
        except Exception as error:
            _log_error(_error_log_path, error)

    @staticmethod
    def get_file_checksum(filename: str, algorithm: HashType, blocksize: int = 2**20) -> str:
        """Generates a calculated checksume for a file given that an approriate algorithm, file path, and blocksize were provided.
        
        Parameters
        ----------
        :param filename: The path of a file used for calculating a checksum.
        :type filename: str\n
        :param algorithm: A `HashType` coroutine to utilize for checksum calculations.
        :type algorithm: HashType\n
        :param blocksize: The size of each block of data to read from a file or binary package.
        :type blocksize: int, optional

        Returns
        -------
        :rtype: str
        :return: The hexadecimal digest of the generated data checksum.
        """
        try:
            if callable(algorithm):
                checksum = algorithm()
                file = open(filename, 'rb')
                while True:
                    data = file.read(blocksize)
                    if not data:
                        break
                    checksum.update(data)
                return checksum.hexdigest()
            else: print("Please provide a valid algorithm to generate a checksum. Currently only MD5, SHA1, SHA224, SHA256, SHA384, and SHA512 are supported.")
        except IOError as error:
            _log_error(_error_log_path, str(error))
        except Exception as error: 
            _log_error(_error_log_path, str(error))

class Scanner:
    @staticmethod
    def scan_system(root_path: str, algorithm: str = "md5", print_to_console: bool = False) -> None:
        """Scans the current local filesystem and creates a map of files and directories using the specified hashing algorithm.
        
        Parameters
        ----------
        :param root_path: The starting path that the application will start scanning from.
        :type root_path: str\n
        :param algorithm: The algorithm used to generate file checksums. Can be MD5, SHA1, SHA224, SHA256, SHA384, or SHA512.
        :type algorithm: str\n
        :param print_to_console: A flag which determines if results should be shown in the terminal.
        :type print_to_console: bool, optional
        """
        def _map_system(root_path: str):
            """Recursively scan and hash files starting from the provided system path.
            
            Parameters
            ----------
            :param root_path: The starting path that the application will start scanning from.
            :type root_path: str\n
            """
            mapfile = open(_hashmap_log_path, 'a')
            try: # Catch any errors related to the scanning of the directory.
                with mapfile as stream:
                    results = os.scandir(root_path)
                    for entry in results:
                        stats = entry.stat()
                        if entry.is_file():
                            try: # Catch any errors related to gathering information about the file.
                                data = f"File: {entry.path}|Size: {stats.st_size}|Permissions: {stats.st_mode}|Device: {stats.st_dev}|"\
                                    f"Device Type: {stats.st_rdev}|Links: {stats.st_nlink}|UID: {stats.st_uid}|GID: {stats.st_gid}|"\
                                    f"Last Accessed: {stats.st_atime}|Last Modified: {stats.st_mtime}|Last Metadata Change: {stats.st_ctime}|"\
                                    f"Unix Inode/Windows Index: {stats.st_ino}|User Flags: {stats.st_flags}|"
                                checksum = Hashing.get_file_checksum(entry.path, HashType.get_type(algorithm))
                                if checksum is None: checksum = "None" # Make sure the checksum is a string for logging.
                                if print_to_console: print(f"{_get_timestamp()}{data}Checksum: {checksum}")
                                stream.write(f"{_get_timestamp()}{data}Checksum: {checksum}\n")
                            except OSError as e: _log_error(_error_log_path, str(e))
                        elif entry.is_dir(follow_symlinks=False): # Make sure to disallow symlinks in order to avoid infinite recursion.
                            data = f"Directory: {entry.path}|Size: {stats.st_size}|Permissions: {stats.st_mode}|Device: {stats.st_dev}|"\
                                    f"Device Type: {stats.st_rdev}|Links: {stats.st_nlink}|UID: {stats.st_uid}|GID: {stats.st_gid}|"\
                                    f"Last Accessed: {stats.st_atime}|Last Modified: {stats.st_mtime}|Last Metadata Change: {stats.st_ctime}|"\
                                    f"Unix Inode/Windows Index: {stats.st_ino}|User Flags: {stats.st_flags}"
                            _log_directory(_directory_log_path, data)
                            _map_system(entry.path)
            except OSError as e: _log_error(_error_log_path, str(e))
            mapfile.close()
        print(f"{_get_timestamp()}[INFO]: Starting system scan.")
        print(f"{_get_timestamp()}[INFO]: Scanning and mapping filesystem...")
        _map_system(root_path)
        print(f"{_get_timestamp()}[PASS]: Scanning done!")

class Program:
    def __init__(self) -> None:
        """Initialize a new instance of the Pathwalk main program for scanning and mapping the entire filesystem."""
        #? We'll start the scan at the root directory of the system and drill down recursively.
        #? Also, we'll use the MD5 hashing algorithm because it is the fastest while retaining security unlike CRC32.
        self.verbose = False # A flag which allows the user to see all of the work the script is doing.
        self.scan_path = "/" # The starting directory the script will use for scanning the system.
        self.hash_algorithm = "MD5" # The hashing algorithm used when gathering relevant file information.

    def _set_hash_algorithm(self: "Program", algorithm: str) -> None:
        """Sets the algorithm used for checksum generation during the mapping of the filesystem.
        
        Parameters
        ----------
        :param algorithm: The algorithm used to generate file checksums. Can be MD5, SHA1, SHA224, SHA256, SHA384, or SHA512.
        :type algorithm: str\n
        """
        algorithms = ["md5", "sha1", "sha224", "sha256", "sha384", "sha512"]
        if algorithm.lower() in algorithms:
            self.hash_algorithm = algorithm.lower()
        else: raise Exception("Please provide a valid algorithm to generate a checksum. Currently only MD5, SHA1, SHA224, SHA256, SHA384, and SHA512 are supported.")

    def _print_greeting(self: "Program") -> None:
        """Displays a welcome message for the user upon initialization of the script without parameters or during usage."""
        greeting = ("======================================\n" +
                    "✨       Welcome to: Pathwalk!       ✨\n" +
                    "======================================\n")
        info = [
            f'⇢ Version\t| Pathwalk (v{_version})[{_version_name}]',
            f'⇢ Author\t| Jason Drawdy (Buddha)',
            f'⇢ Platform\t| Python (v{platform.python_version()})',
            f'⇢ Spawned\t| {datetime.datetime.now()}',
        ]
        line_bar = ""
        line_bar_length = 0
        for bar in info:
            if len(bar) > line_bar_length:
                line_bar_length = len(bar)
        while len(line_bar) != line_bar_length+10:
            line_bar += "-"
        print('\n'+ f"{greeting}")
        print(f"{line_bar}")
        for entry in info:
            print(f"{entry}")
        print(f"{line_bar}")

    def _print_usage(self: "Program") -> None:
        """Displays detailed documentation for the user upon request or misuse of the script."""
        usage = [
            "\n===========================================",
            f"Usage: {os.path.basename(__file__)}: [options] <parameters>",
            "===========================================",
            "-h or --help..............| Displays the current help documentation for the program.",
            "-p or --path..............| The path to utilize during the system scan for the hash map.",
            "-v or --verbose...........| Displays all of the work currently being performed by the script.",
            "-a or --algorithm.........| Determines which algorithm to use during checksum operations.",
            "NOTE: Currently only MD5, SHA1, SHA224, SHA256, SHA384, and SHA512 checksums are supported.",
            "\n===========================================",
            f"Examples: ",
            "===========================================",
            f"Start a root scan.........| {os.path.basename(__file__)}",
            f"Show help documentation...| {os.path.basename(__file__)} -h",
            f"Scan with verbose.........| {os.path.basename(__file__)} -v",
            f"Scan a directory path.....| {os.path.basename(__file__)} -p \"./directory\"",
            f"Scan with an algorithm....| {os.path.basename(__file__)} -a sha1\n",
            f"For more information please visit: https://github.com/jasondrawdy\n"
        ]
        self._print_greeting()
        for line in usage: print(line)

    def _start_scanner(self: "Program") -> None:
        """Starts the file system hash map scanner which will write all output to the respective files."""
        try:
            valid_responses = ["y", "yes", "ok", "sure", "of course", "ofcourse", "duh", "okay", "yep", "yeah", "ye", "alright", "please", "bien", "si"]
            if os.path.exists(_directory_log_path): 
                if input(f"{_get_timestamp()}[WARN]: The file '{_directory_log_path}' already exists. Would you like to overwrite it?: ").lower() in valid_responses:
                    os.remove(_directory_log_path)
                    print(f"{_get_timestamp()}[NOTE]: The file '{_directory_log_path}' will now be overwritten.")
                else: print(f"{_get_timestamp()}[NOTE]: '{_directory_log_path}' will not be deleted and will only be appended to.")
            if os.path.exists(_hashmap_log_path):
                if input(f"{_get_timestamp()}[WARN]: The file '{_hashmap_log_path}' already exists. Would you like to overwrite it?: ").lower() in valid_responses:
                    os.remove(_hashmap_log_path)
                    print(f"{_get_timestamp()}[NOTE]: The file '{_hashmap_log_path}' will now be overwritten.")
                else: print(f"{_get_timestamp()}[NOTE]: '{_hashmap_log_path}' will not be deleted and will only be appended to.")
            if os.path.exists(_error_log_path):
                if input(f"{_get_timestamp()}[WARN]: The file '{_error_log_path}' already exists. Would you like to overwrite it?: ").lower() in valid_responses:
                    os.remove(_error_log_path)
                    print(f"{_get_timestamp()}[NOTE]: The file '{_error_log_path}' will now be overwritten.")
                else: print(f"{_get_timestamp()}[NOTE]: '{_error_log_path}'' will not be deleted and will only be appended to.")
            Scanner.scan_system(self.scan_path, algorithm=self.hash_algorithm, print_to_console=self.verbose)
        except PermissionError as e: print(f"{_get_timestamp()}[FAIL]: {e}\n\nPlease run \"{os.path.basename(__file__)}\" as an administrator!\n")
        except Exception as e: print(f"{_get_timestamp()}[FAIL]: {e}\n")

    def main(self: "Program"):
        """Initializes the application and all of its constiuent parts including variable flags and any other supplied data."""
        _opts = ["ho:v:p:a:", ["help", "verbose", "path=", "algorithm="]]
        try: 
            if "-v" in sys.argv:
                self.verbose = True
                sys.argv.remove("-v")
            opts, args = getopt.getopt(sys.argv[1:], _opts[0], _opts[1])
        except getopt.GetoptError as err:
            message = str(err)
            if re.match('^[A-Z][^?!.]*[?.!]$', message) is None:
                message = f"{message}." #? I like full sentences for my logging; can you or anybody help highlight the opt too?
            self._print_usage()
            print(f"[WARN]: {str(message).capitalize()}\n")
            sys.exit(2)
        parameters = {} #? For now leave the parameter dictionary blank in case we want to extend the script in the future with more features.
        options = []
        error = False
        for o, a in opts:
            if o == "-h" or o == "--help": #? If the help flag is detected anywhere just display it instead of doing anything else.
                error = True
                self._print_usage()
                break
            elif o == "-v" or o == "--verbose": #? Check if the user wants to observe the working being done.
                try: 
                    self.verbose = True
                except Exception as e:
                    print(f"{_get_timestamp()}[FAIL]: {e}\n")
                    sys.exit(2)
            elif o == "-p" or o == "--path": #? Make sure to set the path for the system scanner to use.
                try: 
                    if os.path.exists(a):
                        self.scan_path = a
                    else: raise Exception("Please provide a directory that exists.")
                except Exception as e:
                    print(f"{_get_timestamp()}[FAIL]: {e}\n")
                    sys.exit(2)
            elif o == "-a" or o == "--algorithm": #? Set the algorithm to use during checksum operations if needed.
                try: self._set_hash_algorithm(a)
                except Exception as e:
                    print(f"{_get_timestamp()}[FAIL]: {e}\n")
                    sys.exit(2)
            else: #? Check if there's anything more than the help and the aforementioned flags.
                option = parameters.get(str(o), None)
                if option is not None:
                    options.append((option, a))
                else:
                    error = True
                    self._print_usage()
        if not error: #? Run all of the appropriate functions provided the proper options were given.
            if len(options) > 0:
                for option in options:
                    method, param = option
                    method(param)
            else:
                if len(args) > 0:
                    self._print_usage()
                    print(f"{_get_timestamp()}[FAIL]: Regular arguments without options are not supported. Please read the above help documentation.\n")
                else: 
                    self._print_greeting()
                    self._start_scanner()
        else: sys.exit(2)

#! The following commented lines of code are for Lilith or anyone else to learn from.
#? Below are some basic types for Python 3.
# string = "Hello, World!" #* This is a literal string.
# number = 100 #* This is an integer/int
# decimal = 1.00 #* This is a floating point number; used for precision operations/money.
# elements = ['red', 'blue', 'yellow'] #* Literally a list.
# mapping = {
#     'Age': 20,
#     'Name': "Tester",
#     'Color': "Green"
# }

#? Some more functions such as how to write to a file; i.e. like the above code.
# with open("filename.txt", 'r') as string:
#     print(type(string))
#     print(string.read(1024^2))

# string_literal = "Hello, World" #* This is a literal string.
# print(type(string_literal))
# print(string_literal)
#print(type(string))

#! Below is the start of the actual script.
if __name__ == "__main__": #? Make sure that this is the main script file instead of a class or data file.
    program = Program()
    program.main()
else: pass #? We only want to start the program if we explicitly called this file.
