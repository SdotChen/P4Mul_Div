'''
Author: Shicong Chen
Email: Sdotchen@163.com
Version: 1.0
'''
ingress = bfrt.div.pipe.Ingress

v1 = input("Please input the dividend(0-4294967295)\n")
print("Dividend = ",v1)
v2 = input("Please input the divisor(0-4294967295)\n")
print("Divisor = ",v2)

ingress.mod_val_t.set_default_with_mod_val(dividend=v1,divisor=v2)
print("--------------------------------")
print("Finished, type in 'exit' back to menu")
print("--------------------------------")