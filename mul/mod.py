'''
Author: Shicong Chen
Email: Sdotchen@163.com
Version: 1.0
'''
ingress = bfrt.mul.pipe.Ingress

v1 = input("Please input the first integer(0-4294967295)\n")
print("First integer = ",v1)
v2 = input("Please input the second integer(0-4294967295)\n")
print("Second integer = ",v2)

ingress.mod_val_t.set_default_with_mod_val(val1=v1,val2=v2)
print("--------------------------------")
print("Finished, type in 'exit' back to menu")
print("--------------------------------")