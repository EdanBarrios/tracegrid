// No caller anywhere: shows up as an uncalled edge function.
Deno.serve(() => new Response('id,name\n'));
