import unittest
from pathlib import Path
from streamlit.testing.v1 import AppTest


class UITests(unittest.TestCase):
    def test_results_and_empty_output(self):
        for bits in ("01", ""):
            source = """
from ui import render
def process(bits, mode, block_size, config):
    return dict(bits=OUTPUT, input_bits=4, output_bits=len(OUTPUT),
                stages=[dict(stage='AOPP', input_bits=4, groups=2,
                             accepted=len(OUTPUT), output_bits=len(OUTPUT))])
render('alice', process)
""".replace("OUTPUT", repr(bits))
            app = AppTest.from_string(source).run()
            app.text_area[0].set_value("0101")
            app.button[0].click().run()
            self.assertFalse(app.exception)
            self.assertEqual(app.metric[1].value, str(len(bits)))
            self.assertEqual(len(app.get("download_button")), 1)
            if not bits:
                self.assertIn("No bits survived", app.info[0].value)

    def test_both_entrypoints(self):
        for script, name in (("alice.py", "Alice"), ("bob.py", "Bob")):
            app = AppTest.from_file(str(Path(__file__).resolve().parents[1] / script)).run(timeout=15)
            self.assertFalse(app.exception)
            self.assertEqual(app.title[0].value, f"{name}'s workspace")
            self.assertEqual(app.radio[0].options, ["AOPP", "AD", "AOPP+AD"])
            app.text_area[0].set_value("0102")
            app.button[0].click().run()
            self.assertFalse(app.exception)
            self.assertIn("Use only", app.error[0].value)


if __name__ == "__main__":
    unittest.main()
