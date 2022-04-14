__version__ = '1.0'
__author__ = 'Edan Gurin'

import os.path

import win32con
import win32net
import winreg
import netifaces
import wmi
import subprocess

import kivy
from kivy.app import App
from kivy.clock import Clock
from kivy.core.window import Window
from kivy.lang import Builder
from kivy.uix.button import Button
from kivy.uix.image import Image
from kivy.uix.popup import Popup
from kivy.uix.gridlayout import GridLayout
from kivy.uix.progressbar import ProgressBar
from kivy.uix.widget import Widget
from kivy.config import Config

Config.set('graphics', 'resizable', False)
kivy.require("1.9.1")

'''
Params : 
'''
ui_color = (0.18431372549019607843137254901961, 0.65490196078431372549019607843137, 0.83137254901960784313725490196078)


def GetApps(hive, flag):
    aReg = winreg.ConnectRegistry(None, hive)
    aKey = winreg.OpenKey(aReg, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", 0, win32con.KEY_READ | flag)
    count_subkey = winreg.QueryInfoKey(aKey)[0]
    arr = []
    for i in range(count_subkey):
        try:
            asubkey_name = winreg.EnumKey(aKey, i)
            asubkey = winreg.OpenKey(aKey, asubkey_name)
            arr.append([winreg.QueryValueEx(asubkey, "DisplayName")[0],
                        winreg.QueryValueEx(asubkey, "UninstallString")[0]])
        except EnvironmentError:
            continue
    return arr


def check_network():
    gateways = netifaces.gateways()
    default_gateway = gateways['default'][netifaces.AF_INET][0]
    ping_reply = subprocess.run(["ping", "-n", "1", default_gateway], stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    return ping_reply.returncode == 0 and "unreachable" not in str(ping_reply.stdout)


def check_domain():
    wmi_os = wmi.WMI().Win32_ComputerSystem()[0]
    return wmi_os.PartOfDomain


def check_mcafee():
    return os.path.exists('C:\Program Files\McAfee\Agent\cmdagent.exe') and os.path.exists(
        'C:\Program Files\McAfee\DLP\Agent') and os.path.exists(
        'C:\Program Files\McAfee\Endpoint Security\Adaptive Threat Protection') and os.path.exists(
        'C:\Program Files\McAfee\Endpoint Security\Firewall') and os.path.exists(
        'C:\Program Files\McAfee\Endpoint Security\Threat Prevention')

    # x = GetApps(win32con.HKEY_LOCAL_MACHINE, win32con.KEY_WOW64_32KEY)
    # y = GetApps(win32con.HKEY_LOCAL_MACHINE, win32con.KEY_WOW64_64KEY)
    # z = GetApps(win32con.HKEY_CURRENT_USER, 0)
    #
    # return all(map(lambda each: each in (x + y + z)[0], ["McAfee Agent", "McAfee RSD Sensor", "McAfee Profiler",
    #                                                      "McAfee Data Exchange Layer for MA", "McAfee Active Response"]))


def check_office():
    x = GetApps(win32con.HKEY_LOCAL_MACHINE, win32con.KEY_WOW64_32KEY)
    y = GetApps(win32con.HKEY_LOCAL_MACHINE, win32con.KEY_WOW64_64KEY)
    z = GetApps(win32con.HKEY_CURRENT_USER, 0)

    return [x for x in x + y + z if "Microsoft Office Professional Plus 2019 - en-us" in x] != []


def check_security_groups():
    '''
    groups = subprocess.Popen(["net", "localgroup"],
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE,
                              universal_newlines=True)

    for line in groups.stdout:
        print(line.strip())
        if "Administrators" in line.strip():
            return True
    '''
    try:
        members = win32net.NetLocalGroupGetMembers(None, 'Administrators', 1)
        return all(map(lambda each: each in list(map(lambda d: d['name'], members[0])),
                       ["ggd-0383-Comp", "ggd-0383-Oper", "ggd-0383-Sec"]))
    except win32net.error as error:
        number, context, message = error.args
        # print(message)
        return False


def init_funcs(index):
    if index == 0: return check_network()

    if index == 1: return check_domain()

    if index == 2: return check_mcafee()

    if index == 3: return check_office()

    if index == 4: return check_security_groups()


class Parameter(Widget):
    def __init__(self, label, index, **kwa):
        super(Parameter, self).__init__(**kwa)
        self.index = index
        self.desc = label
        self.sub_layout = None
        self.progress_bar = None
        self.button = None
        self.isExecuted = False
        self.setup_ui(self.desc, False)

    def setup_ui(self, label, isFinished):
        self.sub_layout = GridLayout(rows=1, size=(Window.width * 0.7, 75),
                                     pos=(75, Window.height - 150 - (self.index * 80)))

        self.button = Button(text=label, color=ui_color, font_size=12)

        if isFinished:
            if self.isExecuted:
                icon = Image(source='check_mark.png', size_hint=(1, None), size=(self.progress_bar.width, 50))
                self.sub_layout.add_widget(icon)
                self.button.text = 'Check Successful'
                self.button.color = (0, 1, 0)
            else:
                self.sub_layout.add_widget(
                    Image(source='failed_mark.png', size_hint=(1, None), size=(self.progress_bar.width, 40)))
                self.button.color = (1, 0, 0)
                self.button.text = 'Check Failed'

        else:
            self.progress_bar = ProgressBar(value=1)
            self.sub_layout.add_widget(self.progress_bar)
            self.button.bind(on_release=self.start)

        self.sub_layout.add_widget(Widget(size_hint=(None, None), width=10, height=5))
        self.sub_layout.add_widget(self.button)
        self.add_widget(self.sub_layout)

    def update(self, dt):
        if self.progress_bar.value >= 100:
            self.sub_layout.clear_widgets()
            self.setup_ui(self.desc, True)
            return False

        self.progress_bar.value += 1

    def start(self, dt):
        Clock.schedule_interval(self.update, 1 / 60)
        self.isExecuted = init_funcs(self.index)


class CompTest(Widget):
    def __init__(self, **kwa):
        super(CompTest, self).__init__(**kwa)
        self.layout = GridLayout(cols=1)
        self.setup_window()

        self.popup = Popup(
            title='CHECKING DESKTOP...',
            content=self.layout,
            auto_dismiss=False,
            size=(Window.width, Window.height)
        )

        self.popup.open()

    def setup_window(self):
        self.layout.size_hint = (None, None)
        self.layout.add_widget(Parameter("Network Availability", 0))
        self.layout.add_widget(Parameter("Domain Availability", 1))
        self.layout.add_widget(Parameter("McAfee Components", 2))
        self.layout.add_widget(Parameter("Office Programs", 3))
        self.layout.add_widget(Parameter("Security Groups", 4))
        self.layout.add_widget(Button(text="Terminate", color=(0.7, 0, 0), size_hint=(None, None),
                                      size=(Window.width * 0.95, 75), on_release=self.exit))

    def exit(self, instance):
        App.get_running_app().stop()


class HaBodek(App):
    def build(self):
        Window.size = (500, 600)
        check_mcafee()
        return CompTest()


Builder.load_string("""
<Label>:
    font_size: 28
    font_name : 'RobotoMono-Regular'
    font_kerning : False
""")

if __name__ in "__main__":
    HaBodek().run()

Config.write()
