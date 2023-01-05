ingress = bfrt.mul_verify.pipe.Ingress

# get seq
seq_table = ingress.seq

pkt_num_pipe_entry = seq_table.get(0,from_hw=True)._get_raw_data()
for i in pkt_num_pipe_entry:
    pkt_num_pipe = pkt_num_pipe_entry[i]

print("pkt number = ",pkt_num_pipe[0])

small_table = ingress.small
big_table = ingress.big
result_hi_table = ingress.cal_res_hi
result_lo_table = ingress.cal_res_lo
correct_num = 0

for i in range(pkt_num_pipe[0]):
    
    # get small
    small_pipe_entry = small_table.get(i,from_hw=True)._get_raw_data()
    for j in small_pipe_entry:
        small_pipe = small_pipe_entry[j]
    print("No.",i,", small = ", small_pipe[0])

    # get big
    big_pipe_entry = big_table.get(i,from_hw=True)._get_raw_data()
    for j in big_pipe_entry:
        big_pipe = big_pipe_entry[j]
    print("No.",i,", big = ", big_pipe[0])

    # get result
    # get result_hi
    result_hi_pipe_entry = result_hi_table.get(i,from_hw=True)._get_raw_data()
    for j in result_hi_pipe_entry:
        result_hi_pipe = result_hi_pipe_entry[j]

    # get result_lo
    result_lo_pipe_entry = result_lo_table.get(i,from_hw=True)._get_raw_data()
    for j in result_lo_pipe_entry:
        result_lo_pipe = result_lo_pipe_entry[j]

    result_P4 = result_hi_pipe[0] * 4294967296 + result_lo_pipe[0]
    print("-------------------------------------------")
    print("No.",i)
    print("Python result = ", small_pipe[0] * big_pipe[0])
    print("P4 result = ",result_P4)
    if(small_pipe[0] * big_pipe[0] == result_P4):
        print("Correct!")
        correct_num = correct_num + 1
    else:
        print("Wrong!")
    print("-------------------------------------------")

print("-------------------------------------------")
print("Calculation executed: ", pkt_num_pipe[0])
print("Calculation correct: ", correct_num)
print('Correct rate: {:.2%}'.format( correct_num / pkt_num_pipe[0]))
print("-------------------------------------------")