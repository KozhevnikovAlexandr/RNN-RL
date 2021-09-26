import gym
from gym import spaces
import numpy as np
from scapy.all import rdpcap



class MudbusEnv(gym.Env):

    def __init__(self, path, episode_length, input_ip, output_ip, displacement):
        self.input_alphabet, self.output_alphabet, self.inputs, self.outputs = \
            self.get_modbus_data(path, input_ip, output_ip, displacement)
        self.observation_space = spaces.Box(low=0, high=len(self.input_alphabet),
                                            shape=(1,))
        # self.action_space = spaces.Discrete(len(self.output_alphabet))
        self.action_space = spaces.Box(low=0, high=len(self.output_alphabet),
                                       shape=(1,))
        self.count = 1
        self.last_state = self.inputs[0]
        self.state = self.inputs[1]
        self.last_action = self.inputs[0]
        self.episode_length = episode_length

    def step(self, action):

        reward = 0
        done = False
        info = {}

        if self.count == self.episode_length:
            done = True
        else:
            if self.outputs[self.count] == np.argmax(action):
                reward = 1
            else:
                reward = -1
            self.count += 1
            done = False
            self.last_state = self.state
            self.last_action = action
            self.state = self.inputs[self.count]

        return self.state, reward, done, info

    def reset(self):
        self.state = self.inputs[1]
        self.last_state = self.inputs[0]
        self.last_action = self.outputs[0]
        self.count = 0
        return self.state

    def get_modbus_data(self, path, input_ip, output_ip, displacement):
        pcap = rdpcap(path)
        input_alphabet = dict()
        output_alphabet = dict()
        inputs = []
        outputs = []
        input_count = 0
        output_count = 0
        for i in pcap.res:
            new_data = i['Raw'].load[displacement:]
            if i['IP'].src == input_ip:
                if new_data not in input_alphabet.keys():
                    input_alphabet[new_data] = input_count
                    input_count += 1
                inputs.append(input_alphabet[new_data])

            elif i['IP'].src == output_ip:
                if new_data not in output_alphabet.keys():
                    output_alphabet[new_data] = output_count
                    output_count += 1
                outputs.append(output_alphabet[new_data])

        return input_alphabet, output_alphabet, inputs, outputs


if __name__ == '__main__':
    env = MudbusEnv('/home/user/Projects/OTALA-/modbus_clever_office_131-218_full_bad.pcap', 3000, '192.168.12.131',
                    '192.168.252.218', 6)
    print(env.action_space)
