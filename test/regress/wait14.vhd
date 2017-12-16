entity wait14 is
end entity;

architecture test of wait14 is
    signal x, y : integer;
begin

    wakeup: process is
    begin
        wait for 1 ns;
        assert x = 0;
        assert y = 0;
        wait on x, y for 100 ns;
        assert x = 1;
        assert y = 0;
        wait on x for 100 ns;
        assert x = 2;
        assert y = 1;
        wait;
    end process;

    stimp: process is
    begin
        x <= 0;
        y <= 0;
        wait for 2 ns;
        x <= 1;
        wait for 5 ns;
        y <= 1;                         -- wakeup should not wake here
        wait for 5 ns;
        x <= 2;
        wait;
    end process;

end architecture;
