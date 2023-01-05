ingress = bfrt.div_verify.pipe.Ingress

# get seq
seq_table = ingress.seq

pkt_num_pipe_entry = seq_table.get(0,from_hw=True)._get_raw_data()
for i in pkt_num_pipe_entry:
    pkt_num_pipe = pkt_num_pipe_entry[i]

print("pkt number = ",pkt_num_pipe[0])

dividend_table = ingress.dividend
divisor_table = ingress.divisor
quotient_table = ingress.reg_quotient
remainder_table = ingress.reg_remainder
correct_num = 0

for i in range(pkt_num_pipe[0]):
    
    # get dividend
    dividend_pipe_entry = dividend_table.get(i,from_hw=True)._get_raw_data()
    for j in dividend_pipe_entry:
        dividend_pipe = dividend_pipe_entry[j]
    print("No.",i,", dividend = ", dividend_pipe[0])

    # get divisor
    divisor_pipe_entry = divisor_table.get(i,from_hw=True)._get_raw_data()
    for j in divisor_pipe_entry:
        divisor_pipe = divisor_pipe_entry[j]
    print("No.",i,", divisor = ", divisor_pipe[0])

    # get quotient
    quotient_pipe_entry = quotient_table.get(i,from_hw=True)._get_raw_data()
    for j in quotient_pipe_entry:
        quotient_pipe = quotient_pipe_entry[j]

    # get remainder
    remainder_pipe_entry = remainder_table.get(i,from_hw=True)._get_raw_data()
    for j in remainder_pipe_entry:
        remainder_pipe = remainder_pipe_entry[j]

    print("-------------------------------------------")
    print("No.",i)
    print("Python quotient = ", dividend_pipe[0] // divisor_pipe[0])
    print("P4 quotient = ", quotient_pipe[0])
    print("Python remainder = ", dividend_pipe[0] % divisor_pipe[0])
    print("P4 remainder = ",remainder_pipe[0])
    if dividend_pipe[0] // divisor_pipe[0] == quotient_pipe[0] and dividend_pipe[0] % divisor_pipe[0] == remainder_pipe[0]:
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