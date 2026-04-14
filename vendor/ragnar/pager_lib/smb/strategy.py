class DataStrategyBase():
    DATABYTES_CODEC = 'UTF-16LE'
    
  
class DataFaultToleranceStrategy():
    @staticmethod
    def data_bytes_decode(databytes):
        return databytes.decode(DataStrategyBase.DATABYTES_CODEC, 'ignore')


class DataStrategy():
    @staticmethod
    def data_bytes_decode(databytes):
        return databytes.decode(DataStrategyBase.DATABYTES_CODEC)
        