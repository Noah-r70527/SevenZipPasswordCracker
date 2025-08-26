import py7zr
from datetime import datetime
from concurrent.futures import ProcessPoolExecutor, as_completed
import multiprocessing
import math
import logging

"""
This module allows for the utilization of a password list file to perform a dictionary attack against an encrypted
7zip file. When instantiating this class, you will need:

file_to_crack - The file path to the file you are trying to crack
password_list_file - The .txt file of passwords to be used.
output_dir - The target extraction directory.

After instantiating this class, call the execute_crack function to begin the attempts.

"""


class SevenZipCracker:

    def __init__(self, file_to_crack: str, password_list_file: str, output_dir: str):
        self.file_to_crack = file_to_crack
        self.password_list_file = password_list_file
        self.output_dir = output_dir
        self.password_list = self.__load_password_list()
        self.start_time: datetime = datetime.now()


    def __load_password_list(self):
        """Loading password list."""
        with open(self.password_list_file, 'r', encoding='utf-8', errors='ignore') as f:
            return f.readlines()

    def __attempt_batch(self, args):
        """Worker tries its chunk of passwords, increments global counter via Manager.Value."""
        batch, start_idx, found_event, tries = args
        for password in batch:
            if found_event.is_set():
                return False, None

            tries.value += 1
            attempt_num = tries.value

            logging.info(f"Attempt number {attempt_num} - {password.strip()}")

            try:
                with py7zr.SevenZipFile(self.file_to_crack, mode='r', password=password.strip()) as zipfile:
                    zipfile.extractall(path=self.output_dir)
                    elapsed = (datetime.now() - self.start_time).total_seconds() / 60
                    found_event.set()
                    return (True,
                            f"\n**Password FOUND!**\n"
                            f"Time to crack: {elapsed} minutes\n"
                            f"Number of tries: {attempt_num}\n"
                            f"Password: {password.strip()}")
            
            except Exception:
                continue
        return False, None

    def execute_crack(self, max_threads=4):
        """
        Starts the password cracking process.

        :param max_threads: - specify the max number of threads to utilize.
        :return:
        """
        self.start_time = datetime.now()
        max_workers = min(max_threads, multiprocessing.cpu_count())
        batch_size = math.ceil(len(self.password_list) / max_workers)

        manager = multiprocessing.Manager()
        found_event = manager.Event()
        tries = manager.Value('i', 0)

        batches = [(self.password_list[i:i + batch_size], i + 1, found_event, tries)
                   for i in range(0, len(self.password_list), batch_size)]

        try:
            with ProcessPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(self.__attempt_batch, batch): batch for batch in batches}
    
                for future in as_completed(futures):
                    success, message = future.result()
                    if success:
                        logging.info(message)
                        executor.shutdown(cancel_futures=True)
                        break
    
            logging.info(f"\nTotal attempts made: {tries.value}")
            
        except py7zr.Bad7zFile as e:
            logging.error(f'Invalid 7zip File: {e}')
            
        except py7zr.UnsupportedCompressionMethodError as e:
            logging.error(f'Unsupported Compression Method: {e}')
            
        except py7zr.DecompressionError as e:
            logging.error(f'Decompression error: {e}')



