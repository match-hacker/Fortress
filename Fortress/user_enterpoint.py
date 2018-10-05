#!/usr/bin/env python
# -*- coding:utf-8 -*-
# author: cyp  date: 2018-10-02
import getpass, os
from django.contrib.auth import authenticate
import subprocess
import hashlib, time

class UserPortal(object):
    """用户命令行端交互入口"""

    def __init__(self):
        self.user = None

    def user_auth(self):
        """完成用户交互"""
        retry_count = 0
        while retry_count < 3:
            username = input("Username:").strip()
            if len(username) == 0: continue
            password = getpass.getpass("Password:").strip()
            if len(password) == 0:
                print("Password cannot be null.")
                continue
            user = authenticate(username=username, password=password)
            if user:
                self.user = user
                # print("welcome login...")
                return
            else:
                print("Invalid username or password!")
            retry_count += 1
        else:
            exit("Too many attempts.")

    def interactive(self):
        """交互函数"""
        self.user_auth()
        if self.user:
            exit_flag = False
            while not exit_flag:
                for index, host_group in enumerate(self.user.host_groups.all()):
                    print("%s. %s[%s]" % (index, host_group.name, host_group.bind_hosts.all().count()))
                print("%s. Ungrouped Host[%s]" % (index+1, self.user.bind_hosts.select_related().count()))
                user_input = input("Choose Group:").strip()
                if len(user_input) == 0: continue
                if user_input.isdigit():
                    user_input = int(user_input)
                    if user_input == 0 and user_input < self.user.host_groups.all().count():
                        selected_hostgroup = self.user.host_groups.all()[user_input]
                    elif user_input == self.user.host_groups.all().count():  # 选中了未分组的那组主机，这是很牛逼的方法
                        selected_hostgroup = self.user  # 巧用表结构中 相同的字段名，实现代码复用（表user和host_group下面都有bind_hosts）
                    else:
                        print("Invalid host group")
                        continue
                    while True:
                        for index, bind_host in enumerate(selected_hostgroup.bind_hosts.all()):
                            print("%s. %s(%s user:%s)" % (index,
                                                          bind_host.host.hostname,
                                                          bind_host.host.ip_addr,
                                                          bind_host.host_user.username))
                        user_input2 = input("Choose Host:").strip()
                        if len(user_input2) == 0: continue
                        if user_input2.isdigit():
                            user_input2 = int(user_input2)
                            if user_input2 == 0 and user_input2 < selected_hostgroup.bind_hosts.all().count():
                                selected_bindhost = selected_hostgroup.bind_hosts.all()[user_input2]
                                print("logging host", selected_bindhost)
                                md5_str = hashlib.md5(str(time.time()).encode()).hexdigest()
                                login_cmd = 'sshpass  -p {password} ssh {user}@{ip_addr}  -o "StrictHostKeyChecking no" -i {md5_str}'.format(password=selected_bindhost.host_user.password, user=selected_bindhost.host_user.username, ip_addr=selected_bindhost.host.ip_addr, md5_str=md5_str)

                                print(login_cmd)
                                #start session tracker script 
                                session_tracker_script = settings.SESSION_TRACKER_SCRIPT 
                                tracker_obj = subprocess.Popen("%s %s" %(session_tracker_script, md5_str), shell=True, stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd=settings.BASE_DIR)
                               # time.sleep(15)
                                #create session log
                                models.SessionLog.objects.create(user=self.user,bind_host=selected_bindhost, session_tag = md5_str)
                                ssh_instance = subprocess.run(login_cmd, shell=True)
                                print('---------------------------logout--------------------------------')
                                print("session tracker output", tracker_obj.stdout.read().decode(), tracker_obj.stderr.read().decode() )
                        if user_input2 == "b":
                            break


if __name__ == "__main__":
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Fortress.settings')
    import django
    django.setup()
    from audit import models
    from django.conf import settings
    portal = UserPortal()
    portal.interactive()














