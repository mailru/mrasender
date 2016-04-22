--------------------------------------------------------------------------------
--- A Lua submodule
--------------------------------------------------------------------------------

local function func(a, b, c, d)
    -- Check arguments for all public functions
    if a == nil or b == nil or c == nil or d == nil then
        error('Usage: functions.func(username: string, password: string, recipient: string, msg: string)')
    end
    return
end

-- result is returned from require('mrasender.functions')
return {
    func = func;
}
-- vim: syntax=lua ts=4 sts=4 sw=4 et
