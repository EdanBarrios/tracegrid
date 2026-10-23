// Called by a payment provider, not by the app. Listed in supagraph.config.json ignore.
Deno.serve(async (req) => new Response(await req.text()));
