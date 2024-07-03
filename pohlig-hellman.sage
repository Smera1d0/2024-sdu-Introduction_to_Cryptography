def Polig_Hellman(g,y,p):
    factors, exponents = zip(*factor(p-1))
    temp=[]
    for i in range(len(factors)):
        q=factors[i]
        a=[]
        for j in range(1,exponents[i]+1):
            gg=pow(g,((p-1)//q^j),p)
            yy=pow(y,((p-1)//q^j),p)
            for k in range(q):
                s=0
                for t in range(len(a)):
                    s+=a[t]*q^t
                s+=k*q^(len(a))
                if pow(gg,s,p)==yy:
                    a.append(k)
                    break
        x_q=0
        for j in range(len(a)):
            x_q+=a[j]*q^j
        temp.append(x_q)
    f=[]
    for i in range(len(factors)):
        f.append(factors[i]^exponents[i])
    print(temp)
    return crt(temp,f)

#print(Polig_Hellman(6,29,41))
#print(Polig_Hellman(2,29,37))
F=GF(41)
print(discrete_log(F(29),F(6))==Polig_Hellman(6,29,41))
G=GF(37)
print(discrete_log(G(29),G(2))==Polig_Hellman(2,29,37))
