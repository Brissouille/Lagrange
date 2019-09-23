from dfa import DFA

dfa = DFA()
key = "2B7E151628AED2A6ABF7158809CF4F3C"
message = "3243F6A8885A308D313198A2E0370734"

fault = [0x1e, 0xe1, 0xb3, 0x16, 0x9e]

dfa.encrypt(key, message, 9, 0, fault)

dfa.reset()

# exploit faults

exploit_list = [["de25841d02dc0962dc11c297193b0b32", "3925841d02dc09fbdc118597196a0b32"],
                ["f325841d02dc097edc11719719510b32", "3925841d02dc09fbdc118597196a0b32"],
                ["4025841d02dc09f9dc118f97196e0b32", "3925841d02dc09fbdc118597196a0b32"],
                ["1625841d02dc09bfdc11659719d20b32", "3925841d02dc09fbdc118597196a0b32"],
                ["9b25841d02dc09d5dc115c97197e0b32", "3925841d02dc09fbdc118597196a0b32"]]

dfa.exploit(9, 0, exploit_list)
