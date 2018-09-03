import getpass
import json
import os
from pprint import pprint
try:
    from . import rsa_file_func
    from . import file_path_setting
except (Exception, ) as e:
    import rsa_file_func
    import file_path_setting

SHOW_PASSWORD = True


def _insert_bracket(str_): return f'({str_[:3]}){str_[3:]}'


def input_with_msg(msg, show_input=True):
    print(msg)
    if show_input:
        print('input: ', end='', flush=True)
        return input()
    else:
        return getpass.getpass(prompt='Password: ')


class PassPacker():
    def __init__(self):
        self.unlocked = False
        self.password_filepath = file_path_setting.PASSWORD_FILEPATH
        self.rsakey_filepath = file_path_setting.RSAKEY_FILEPATH

    def __call__(self, arg_password):
        self.unlock(arg_password)
        return dict(self.password_dict.items())

    def return_dict(self):
        self.unlock()
        return dict(self.password_dict.items())

    def unlock(self, arg_password=None):
        if self.unlocked:
            return
        if not os.path.isfile(self.rsakey_filepath):
            print(self.rsakey_filepath)
            self.passphrase = input_with_msg(
                "set the password", show_input=True)
            rsa_file_func.gen_rsa_key(self.passphrase, self.rsakey_filepath)
        if os.path.isfile(self.password_filepath):
            while True:
                if arg_password is None:
                    self.passphrase = input_with_msg(
                        '', show_input=SHOW_PASSWORD)
                else:
                    self.passphrase = arg_password
                try:
                    string_data = rsa_file_func.decrypt_data(
                        self.password_filepath, self.rsakey_filepath, self.passphrase)
                except (Exception, ) as e:
                    print(f"{self.passphrase} didn't match")
                else:
                    break
            self.password_dict = json.loads(string_data)
        else:
            self.password_dict = {}
        self.unlocked = True

    def all_show(self):
        self.unlock()
        pprint(self.password_dict)

    def raw_all_show(self):
        self.unlock()
        print(self.password_dict)

    def overwrite(self):
        self.unlock()
        string_ = json.dumps(self.password_dict)
        rsa_file_func.encrypt_data(self.password_filepath, self.rsakey_filepath,
                                   self.passphrase, string_)
        print("saved")

    def show_one(self):
        key = input_with_msg('input key')
        print(self.password_dict[key])

    def find(self):
        self.unlock()
        keyword = input_with_msg(
            'will show keys which contains input', show_input=True)
        [print(key) for key in self.password_dict.keys() if keyword in key]

    def add_password(self):
        self.unlock()
        key = input_with_msg('new key')
        password = input_with_msg('new password')
        self.password_dict[key] = password
        self.overwrite()

    def dict_add_password(self):
        self.unlock()
        input_ = input_with_msg('add passwords as dict string')
        passwords_dict = eval(input_)
        for key, value in passwords_dict.items():
            self.password_dict[key] = value
        self.overwrite()

    def __getitem__(self, key, password=None):
        self.unlock(password)
        key_lower = key.lower()
        if key_lower not in self.password_dict:
            print(key_lower, 'is missing.')
        return self.password_dict[key_lower]

    def change_key(self):
        self.unlock()
        old_key_name = input_with_msg("old key name")
        new_key_name = input_with_msg("new key name")
        password = self.password_dict[old_key_name]
        del self.password_dict[old_key_name]
        self.password_dict[new_key_name] = password
        self.overwrite()

    def exit(self):
        Exception("not prepared yet.")

    def recv_commands(self):
        funcs = [self.show_one, self.all_show, self.raw_all_show, self.find,
                 self.add_password, self.dict_add_password, self.change_key, self.exit]
        names = [_insert_bracket(f.__name__) for f in funcs]
        dict_input_to_names = {
            name[1: 4]:  func for name, func in zip(names, funcs)}
        while True:
            print(f'commands:{names}')
            input_ = input()
            if input_ in dict_input_to_names:
                func = dict_input_to_names[input_]
                func()
            else:
                print(f"input:{[input_, ]} don't match anything")


passwords = PassPacker()

if __name__ == '__main__':
    passwords.unlock()
    passwords.recv_commands()
