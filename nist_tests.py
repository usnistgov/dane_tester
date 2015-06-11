import dane_checker


if __name__=="__main__":
    for line in open("tlsa-list-full.txt"):
        line = line.strip()
        if line[0]=='#':
            print(line)
            continue
        print("\n==== {} ====".format(line))
        dane_checker.print_test_results(dane_checker.tlsa_http_verify(line))

            
