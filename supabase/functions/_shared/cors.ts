export const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  // The server's clock, which a client whose own is wrong signs its SIWS
  // message by (API.md, "The message's time"). Browsers hide it otherwise.
  'Access-Control-Expose-Headers': 'date',
}