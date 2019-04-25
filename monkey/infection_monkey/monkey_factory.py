from infection_monkey.model import MONKEY_ARG, DROPPER_ARG

class RunnableMonkey(object):
    # TODO define interface which will be a the parent of InfectionMonkey and MonkeyDrops

class RunnableMonkeyFactory(object):
    @staticmethod
    def create_runnable_monkey(run_mode):
        if run_mode == MONKEY_ARG:
            # todo init and return infection monkey
        elif run_mode == DROPPER_ARG:
            # todo init and return dropper
        else:
            raise NotImplementedError()
        