package jitperf is
end package;

package body jitperf is

    function fact(x : natural) return natural is
        variable result : natural := 1;
    begin
        for i in 2 to x loop
            result := result * i;
        end loop;
        return result;
    end function;

    type int_vector is array (natural range <>) of integer;

    function sum(a : int_vector) return integer is
        variable result : integer := 0;
    begin
        for i in a'range loop
            result := result + a(i);
        end loop;
        return result;
    end function;

end package body;
