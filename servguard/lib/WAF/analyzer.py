"""

Analyzer Module responsible for analyzing HTTP Request
Segregates HTTP Request as malacious or not
"""

import pandas as pd
import numpy as np
import warnings
import os


from servguard import logger
from joblib import load
from pathlib import  Path



class MlAnalyzer():
    """
    ML analyzer to detect whether a given parameter is malacious or not
    """

    def __init__(self,path):


        warnings.filterwarnings("ignore", category=UserWarning)
        self.path=path

        self.MODEL_PATH= Path(os.path.dirname(__file__)).parent /"/Models/rf-model1"


        self.logger=logger.ServGuardLogger(
            __name__,
            debug=True
        )

    def loadmodel(self):

        try:
            self.model=load("./Models/svm-model1")
        except Exception as e:
            self.logger.log(
                e,
                logtype="error"
            )
    def predictor(self):

        # converting data into numpy array
        self.livepath=np.array([self.path])
        self.type=self.model.predict(self.livepath)
        return self.type

