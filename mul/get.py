'''
Author: Shicong Chen
Email: Sdotchen@163.com
Version: 1.0
'''
ingress = bfrt.mul.pipe.Ingress

hi_arr=ingress.cal_res_hi.get(0,from_hw=True)._get_raw_data()
lo_arr=ingress.cal_res_lo.get(0,from_hw=True)._get_raw_data()

hi = 0
lo = 0

for pipe in hi_arr:
    hi = hi_arr[pipe]
for pipe in lo_arr:
    lo = lo_arr[pipe]
if(hi[0] == 0):
    print("result = ",hi[0]*4294967296 + lo[0])
else:
    print("result = ",hi[0]," * 4294967296 + ",lo[0]," = ",hi[0]*4294967296 + lo[0])