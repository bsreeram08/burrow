import { expect, test } from 'bun:test';

test('index.html ids are unique (a duplicate makes getElementById find the wrong element)', async () => {
  const html = await Bun.file(new URL('../../packages/signaling/public/index.html', import.meta.url)).text();
  const ids = [...html.matchAll(/\sid="([^"]+)"/g)].map(match => match[1]);
  expect(ids.filter((id, at) => ids.indexOf(id) !== at)).toEqual([]);
});
