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

end package body;
