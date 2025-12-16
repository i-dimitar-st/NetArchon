-- lib.lua
function compute_percentile(samples, percentile)
    table.sort(samples)
    local n = #samples
    local idx = math.floor(percentile / 100 * n)
    if idx < 1 then idx = 1 end
    if idx > n then idx = n end
    return samples[idx]
end

-- Computes requested percentiles from a list of numeric samples
-- @samples: table of numeric values (unsorted)
-- @percentiles: table of percentile values (0-100) to compute
-- Returns: table mapping percentile -> value
function compute_stats(samples, percentiles)
    local results = {}
    for _, p in ipairs(percentiles) do
        results[p] = compute_percentile(samples, p)
    end
    return results
end
