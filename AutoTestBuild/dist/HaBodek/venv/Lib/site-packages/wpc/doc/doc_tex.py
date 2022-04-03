import os
from abc import ABC

from wpc.doc import Doc


class DocTex(Doc, ABC):

    def ext_src(self):
        return 'tex'
