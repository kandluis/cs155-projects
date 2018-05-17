# Part 2: Defenses

## Attack Alpha
Attack Alpha relies on unsanatized user input being rendered to the page. We can avoid this attack (and other similar attacks), by simply sanatizing the user input by escaping all HTML related characters in any input provided by the user. While somewhat excessive, this is the easiest and most straight-forward way of knowing that the input is safe. Alternatively, we could keep a whitelist of allowed tags (such as <p>), but we'd rather err on the side of security.

## Attack Bravo