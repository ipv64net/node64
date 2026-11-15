-- Das Interface gilt jetzt auch fuer die Modi "prefix" und "suffix" (Praefix von diesem Interface, #154). Bisher
-- blieb es nach einem Wechsel weg vom Modus "iface" stehen und wurde ignoriert; damit sich solche Ziele nach dem
-- Update nicht anders verhalten, wird es bei allen anderen Modi geleert.
UPDATE dyn_targets SET iface = '' WHERE mode6 <> 'iface';
