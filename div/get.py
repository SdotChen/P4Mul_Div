'''
Author: Shicong Chen
Email: Sdotchen@163.com
Version: 1.0
'''
ingress = bfrt.div.pipe.Ingress

reg_quotient=ingress.reg_quotient.get(0,from_hw=True)._get_raw_data()
reg_remainder=ingress.reg_remainder.get(0,from_hw=True)._get_raw_data()

hi = 0
lo = 0

for pipe in reg_quotient:
    quotient = reg_quotient[pipe]
for pipe in reg_remainder:
    remainder = reg_remainder[pipe]

print("quotient = ",quotient[0])
print("remainder = ",remainder[0])