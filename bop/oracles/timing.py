from time import sleep


class CompareTimingLeakOracle(object):
    def __init__(self, delay=20):
        self.delay = delay * 0.001

    def __call__(self, lhs, rhs):
        for left, right in zip(lhs, rhs):
            if left != right:
                return False
            sleep(self.delay)

        return True
