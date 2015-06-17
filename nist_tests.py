import dane_checker


if __name__=="__main__":
    import sys
    fn = "tlsa-list-full.txt"
    if len(sys.argv)>1:
        fn = sys.argv[1]
    for line in open(fn):
        line = line.strip()
        if line[0]=='#':
            print(line)
            continue
        print("\n==== {} ====".format(line))
        if "http" in line:
            dane_checker.process_http(line)
        else:
            dane_checker.process_smtp(line)
    dane_checker.print_stats()

            
