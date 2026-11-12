"""Static tests for the Textual control center (no Textual dependency)."""
import ast
from pathlib import Path
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "fido-tui.py"


def parse_tui():
    return ast.parse(SCRIPT.read_text(encoding="utf-8"))


def extract_actions(tree):
    for node in tree.body:
        if isinstance(node, ast.Assign):
            if any(isinstance(target, ast.Name) and target.id == "ACTIONS"
                   for target in node.targets):
                return ast.literal_eval(node.value)
    raise AssertionError("ACTIONS missing")


def extract_css(tree):
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == "GuardUI":
            for child in node.body:
                if isinstance(child, ast.Assign) and any(
                    isinstance(target, ast.Name) and target.id == "CSS"
                    for target in child.targets
                ):
                    return ast.literal_eval(child.value)
    raise AssertionError("GuardUI.CSS missing")


class ResponsiveControlCenterTests(unittest.TestCase):
    def test_menu_actions_are_unique_and_short(self):
        actions = extract_actions(parse_tui())
        self.assertEqual(len(actions), 22)
        self.assertEqual([item[0] for item in actions],
                         [str(i) for i in range(1, 23)])
        self.assertEqual(len({item[0] for item in actions}), len(actions))
        for identifier, label, group, description in actions:
            with self.subTest(action=identifier):
                self.assertLessEqual(len(label), 36)
                self.assertTrue(group and description)

    def test_css_hides_details_on_compact_terminals(self):
        css = extract_css(parse_tui())
        self.assertIn("Screen.compact #right { display: none; }", css)
        self.assertIn("Screen.compact #left { width: 1fr;", css)
        self.assertIn("Screen.tiny #hero", css)
        self.assertIn("overflow-y: auto", css)
        self.assertIn("text-wrap: nowrap", css)

    def test_status_is_rendered_without_new_subprocess_per_resize(self):
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("def on_resize(", source)
        self.assertIn("self.render_health()", source)
        self.assertIn("width < 112", source)
        self.assertIn("width < 66 or height < 27", source)


if __name__ == "__main__":
    unittest.main()
