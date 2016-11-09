library ieee;
use ieee.std_logic_1164.all;

entity dff is
    port (
        clk : in std_logic;
        d   : in std_logic;
        q   : out std_logic );
end entity;

architecture rtl of dff is
begin

    sync_p: process (clk) is
    begin
        if rising_edge(clk) then
            q <= d;
        end if;
    end process;

end architecture;
