"""
Unit tests for payloads in payloads/games/.
"""

import importlib
import os

import pytest

PAYLOADS_DIR = os.path.join(
    os.path.dirname(__file__), os.pardir, "payloads", "games"
)


def _safe_import(module_name):
    try:
        return importlib.import_module(module_name)
    except (SystemExit, PermissionError, OSError) as exc:
        pytest.skip(f"Cannot import {module_name}: {exc}")
        return None


def _read_source(filename):
    path = os.path.join(PAYLOADS_DIR, filename)
    with open(path) as fh:
        return fh.read()


# =========================================================================
# game_snake.py
# =========================================================================
class TestGameSnake:
    def test_import_smoke(self):
        mod = _safe_import("payloads.games.game_snake")
        assert mod is not None

    def test_grid_to_px(self):
        mod = _safe_import("payloads.games.game_snake")
        left, top, right, bottom = mod.grid_to_px(0, 0)
        assert left == 0
        assert top == 0
        assert right == mod.CELL
        assert bottom == mod.CELL

    def test_grid_to_px_nonzero(self):
        mod = _safe_import("payloads.games.game_snake")
        left, top, right, bottom = mod.grid_to_px(3, 5)
        assert left == 3 * mod.CELL
        assert top == 5 * mod.CELL

    def test_opposite_true(self):
        mod = _safe_import("payloads.games.game_snake")
        assert mod.opposite((1, 0), (-1, 0)) is True
        assert mod.opposite((0, 1), (0, -1)) is True

    def test_opposite_false(self):
        mod = _safe_import("payloads.games.game_snake")
        assert mod.opposite((1, 0), (0, 1)) is False
        assert mod.opposite((1, 0), (1, 0)) is False

    def test_random_empty_cell(self):
        mod = _safe_import("payloads.games.game_snake")
        exclude = [(0, 0), (1, 1)]
        pos = mod.random_empty_cell(exclude)
        assert pos not in exclude


# =========================================================================
# game_tetris.py
# =========================================================================
class TestGameTetris:
    def test_import_smoke(self):
        mod = _safe_import("payloads.games.game_tetris")
        assert mod is not None

    def test_rotate(self):
        mod = _safe_import("payloads.games.game_tetris")
        shape = [[1, 0], [1, 0], [1, 1]]
        rotated = mod.rotate(shape)
        assert len(rotated) > 0
        # Rotating a 3x2 gives a 2x3
        assert len(rotated) == 2
        assert len(rotated[0]) == 3

    def test_can_place_empty_board(self):
        mod = _safe_import("payloads.games.game_tetris")
        board = [[None] * mod.BOARD_W for _ in range(mod.BOARD_H)]
        shape = [[1, 1], [1, 1]]
        assert mod.can_place(board, shape, 0, 0) is True

    def test_can_place_out_of_bounds(self):
        mod = _safe_import("payloads.games.game_tetris")
        board = [[None] * mod.BOARD_W for _ in range(mod.BOARD_H)]
        shape = [[1, 1], [1, 1]]
        assert mod.can_place(board, shape, mod.BOARD_W, 0) is False

    def test_clear_lines(self):
        mod = _safe_import("payloads.games.game_tetris")
        board = [[None] * mod.BOARD_W for _ in range(mod.BOARD_H)]
        # Fill last row completely
        board[-1] = ["#"] * mod.BOARD_W
        new_board, cleared = mod.clear_lines(board)
        assert cleared == 1
        assert len(new_board) == mod.BOARD_H

    def test_merge_piece(self):
        mod = _safe_import("payloads.games.game_tetris")
        board = [[None] * mod.BOARD_W for _ in range(mod.BOARD_H)]
        shape = [[1]]
        mod.merge(board, shape, 0, 0, "#FF0000")
        assert board[0][0] == "#FF0000"


# =========================================================================
# game_2048.py
# =========================================================================
class TestGame2048:
    def test_import_smoke(self):
        mod = _safe_import("payloads.games.game_2048")
        assert mod is not None

    def test_compress(self):
        mod = _safe_import("payloads.games.game_2048")
        assert mod.compress([0, 2, 0, 4]) == [2, 4, 0, 0]

    def test_compress_no_gaps(self):
        mod = _safe_import("payloads.games.game_2048")
        assert mod.compress([2, 4, 8, 16]) == [2, 4, 8, 16]

    def test_merge_adjacent(self):
        mod = _safe_import("payloads.games.game_2048")
        line = [2, 2, 0, 0]
        merged, score = mod.merge(line)
        assert merged[0] == 4
        assert merged[1] == 0
        assert score == 4

    def test_move_left(self):
        mod = _safe_import("payloads.games.game_2048")
        board = [
            [0, 2, 0, 2],
            [0, 0, 0, 0],
            [0, 0, 0, 0],
            [0, 0, 0, 0],
        ]
        new_board, moved, score = mod.move_left(board)
        assert new_board[0][0] == 4
        assert moved is True
        assert score == 4

    def test_rotate(self):
        mod = _safe_import("payloads.games.game_2048")
        board = [
            [1, 2, 3, 4],
            [5, 6, 7, 8],
            [9, 10, 11, 12],
            [13, 14, 15, 16],
        ]
        rotated = mod.rotate(board)
        assert rotated[0][0] == 13
        assert rotated[0][3] == 1

    def test_can_move_empty(self):
        mod = _safe_import("payloads.games.game_2048")
        board = [[0] * 4 for _ in range(4)]
        assert mod.can_move(board) is True

    def test_can_move_no_moves(self):
        mod = _safe_import("payloads.games.game_2048")
        board = [
            [2, 4, 8, 16],
            [16, 8, 4, 2],
            [2, 4, 8, 16],
            [16, 8, 4, 2],
        ]
        assert mod.can_move(board) is False

    def test_move_direction(self):
        mod = _safe_import("payloads.games.game_2048")
        board = [
            [0, 0, 0, 2],
            [0, 0, 0, 0],
            [0, 0, 0, 0],
            [0, 0, 0, 0],
        ]
        new_b, moved, _ = mod.move(board, 0)  # left
        assert new_b[0][0] == 2
        assert moved is True


# =========================================================================
# game_Breakout.py
# =========================================================================
class TestGameBreakout:
    def test_import_smoke(self):
        mod = _safe_import("payloads.games.game_Breakout")
        assert mod is not None

    def test_intersect_overlap(self):
        mod = _safe_import("payloads.games.game_Breakout")
        assert mod.intersect((0, 0, 10, 10), (5, 5, 15, 15)) is True

    def test_intersect_no_overlap(self):
        mod = _safe_import("payloads.games.game_Breakout")
        assert mod.intersect((0, 0, 10, 10), (20, 20, 30, 30)) is False

    def test_create_bricks(self):
        mod = _safe_import("payloads.games.game_Breakout")
        bricks = mod.create_bricks()
        assert isinstance(bricks, list)
        assert len(bricks) > 0

    def test_has_main(self):
        mod = _safe_import("payloads.games.game_Breakout")
        assert hasattr(mod, "main") or callable(getattr(mod, "main", None))

    def test_has_pins(self):
        mod = _safe_import("payloads.games.game_Breakout")
        assert hasattr(mod, "PINS")


# =========================================================================
# game_flappy.py
# =========================================================================
class TestGameFlappy:
    def test_import_smoke(self):
        mod = _safe_import("payloads.games.game_flappy")
        assert mod is not None

    def test_create_initial_state(self):
        mod = _safe_import("payloads.games.game_flappy")
        state = mod._create_initial_state()
        assert state["alive"] is True
        assert state["score"] == 0
        assert len(state["pipes"]) == 3

    def test_create_pipe(self):
        mod = _safe_import("payloads.games.game_flappy")
        pipe = mod._create_pipe(200)
        assert pipe["x"] == 200.0
        assert "gap_top" in pipe

    def test_check_collision_safe(self):
        mod = _safe_import("payloads.games.game_flappy")
        state = mod._create_initial_state()
        assert mod._check_collision(state) is False

    def test_check_collision_ground(self):
        mod = _safe_import("payloads.games.game_flappy")
        state = mod._create_initial_state()
        state["bird_y"] = float(mod.GROUND_Y)
        assert mod._check_collision(state) is True

    def test_update_state_not_started(self):
        mod = _safe_import("payloads.games.game_flappy")
        state = mod._create_initial_state()
        updated = mod._update_state(state)
        assert updated["bird_y"] == state["bird_y"]  # no movement


# =========================================================================
# game_minesweeper.py
# =========================================================================
class TestGameMinesweeper:
    def test_import_smoke(self):
        mod = _safe_import("payloads.games.game_minesweeper")
        assert mod is not None

    def test_make_board(self):
        mod = _safe_import("payloads.games.game_minesweeper")
        mines, counts, revealed, flagged = mod._make_board()
        # Check dimensions
        assert len(mines) == mod.GRID_H
        assert len(mines[0]) == mod.GRID_W
        # Mine count
        mine_count = sum(1 for r in mines for c in r if c)
        assert mine_count == mod.MINE_COUNT

    def test_check_win_false(self):
        mod = _safe_import("payloads.games.game_minesweeper")
        mines, counts, revealed, flagged = mod._make_board()
        assert mod._check_win(mines, revealed) is False

    def test_check_win_true(self):
        mod = _safe_import("payloads.games.game_minesweeper")
        mines, _, revealed, _ = mod._make_board()
        # Reveal all non-mine cells
        for r in range(mod.GRID_H):
            for c in range(mod.GRID_W):
                if not mines[r][c]:
                    revealed[r][c] = True
        assert mod._check_win(mines, revealed) is True

    def test_count_flags(self):
        mod = _safe_import("payloads.games.game_minesweeper")
        flagged = [[False] * mod.GRID_W for _ in range(mod.GRID_H)]
        flagged[0][0] = True
        flagged[1][1] = True
        assert mod._count_flags(flagged) == 2

    def test_flood_reveal(self):
        mod = _safe_import("payloads.games.game_minesweeper")
        counts = [[0] * mod.GRID_W for _ in range(mod.GRID_H)]
        revealed = [[False] * mod.GRID_W for _ in range(mod.GRID_H)]
        flagged = [[False] * mod.GRID_W for _ in range(mod.GRID_H)]
        new_revealed = mod._flood_reveal(counts, revealed, flagged, 0, 0)
        # All zeros should be revealed
        assert new_revealed[0][0] is True


# =========================================================================
# game_pong.py
# =========================================================================
class TestGamePong:
    def test_import_smoke(self):
        mod = _safe_import("payloads.games.game_pong")
        assert mod is not None

    def test_create_initial_state(self):
        mod = _safe_import("payloads.games.game_pong")
        state = mod._create_initial_state()
        assert "ball_x" in state
        assert "ball_y" in state
        assert "player_y" in state
        assert "ai_y" in state
        assert state["player_score"] == 0
        assert state["ai_score"] == 0

    def test_update_ball_returns_state(self):
        mod = _safe_import("payloads.games.game_pong")
        state = mod._create_initial_state()
        new_state = mod._update_ball(state)
        assert "ball_x" in new_state

    def test_update_ai(self):
        mod = _safe_import("payloads.games.game_pong")
        state = mod._create_initial_state()
        new_state = mod._update_ai(state)
        assert "ai_y" in new_state


# =========================================================================
# game_space_invaders.py
# =========================================================================
class TestGameSpaceInvaders:
    def test_import_smoke(self):
        mod = _safe_import("payloads.games.game_space_invaders")
        assert mod is not None

    def test_make_state(self):
        mod = _safe_import("payloads.games.game_space_invaders")
        state = mod._make_state()
        assert state["lives"] == mod.MAX_LIVES
        assert state["score"] == 0
        assert state["game_over"] is False
        assert len(state["aliens"]) > 0

    def test_move_bullets(self):
        mod = _safe_import("payloads.games.game_space_invaders")
        state = mod._make_state()
        state["player_bullets"] = [{"x": 60, "y": 50}]
        mod._move_bullets(state)
        assert state["player_bullets"][0]["y"] < 50

    def test_alien_count(self):
        mod = _safe_import("payloads.games.game_space_invaders")
        state = mod._make_state()
        expected = mod.ALIEN_ROWS * mod.ALIEN_COLS
        assert len(state["aliens"]) == expected

    def test_shields_exist(self):
        mod = _safe_import("payloads.games.game_space_invaders")
        state = mod._make_state()
        assert len(state["shields"]) == 3
        assert all(isinstance(s, set) for s in state["shields"])


# =========================================================================
# conways_game_of_life.py
# =========================================================================
class TestConwaysGameOfLife:
    def test_import_smoke(self):
        mod = _safe_import("payloads.games.conways_game_of_life")
        assert mod is not None

    def test_make_grid(self):
        mod = _safe_import("payloads.games.conways_game_of_life")
        grid = mod.make_grid(0)
        assert len(grid) == mod.ROWS
        assert len(grid[0]) == mod.COLS
        assert all(cell == 0 for row in grid for cell in row)

    def test_step_empty_grid(self):
        mod = _safe_import("payloads.games.conways_game_of_life")
        grid = mod.make_grid(0)
        new_grid, alive = mod.step(grid)
        assert alive == 0

    def test_step_blinker(self):
        mod = _safe_import("payloads.games.conways_game_of_life")
        grid = mod.make_grid(0)
        # Horizontal blinker at row 5
        grid[5][4] = 1
        grid[5][5] = 1
        grid[5][6] = 1
        new_grid, alive = mod.step(grid)
        assert alive == 3
        # Should become vertical
        assert new_grid[4][5] == 1
        assert new_grid[5][5] == 1
        assert new_grid[6][5] == 1


# =========================================================================
# game_pacman.py
# =========================================================================
class TestGamePacman:
    def test_import_smoke(self):
        mod = _safe_import("payloads.games.game_pacman")
        assert mod is not None

    def test_parse_maze(self):
        mod = _safe_import("payloads.games.game_pacman")
        maze = mod._parse_maze()
        assert isinstance(maze, list)
        assert len(maze) > 0

    def test_count_dots(self):
        mod = _safe_import("payloads.games.game_pacman")
        maze = mod._parse_maze()
        dots = mod._count_dots(maze)
        assert dots > 0

    def test_can_move(self):
        mod = _safe_import("payloads.games.game_pacman")
        maze = mod._parse_maze()
        # Walls are 1, so find an open space
        # Start position is typically open
        assert mod._can_move(maze, 7, 11, 0, 0) is True

    def test_clamp(self):
        mod = _safe_import("payloads.games.game_pacman")
        x, y = mod._clamp(-1, -1)
        assert x >= 0
        assert y >= 0

    def test_ghost_class(self):
        mod = _safe_import("payloads.games.game_pacman")
        g = mod.Ghost(0, 7, 7)
        assert g.idx == 0
        assert g.scared is False


# =========================================================================
# game_tictactoe.py
# =========================================================================
class TestGameTicTacToe:
    def test_import_smoke(self):
        mod = _safe_import("payloads.games.game_tictactoe")
        assert mod is not None

    def test_source_has_main(self):
        src = _read_source("game_tictactoe.py")
        assert "def main" in src or "def play" in src

    def test_source_has_board_logic(self):
        src = _read_source("game_tictactoe.py")
        assert "win" in src.lower()


# =========================================================================
# game_simon.py
# =========================================================================
class TestGameSimon:
    def test_import_smoke(self):
        mod = _safe_import("payloads.games.game_simon")
        assert mod is not None

    def test_source_has_play(self):
        src = _read_source("game_simon.py")
        assert "def play" in src

    def test_source_has_flash_quad(self):
        src = _read_source("game_simon.py")
        assert "def flash_quad" in src


# =========================================================================
# game_frogger.py
# =========================================================================
class TestGameFrogger:
    def test_import_smoke(self):
        mod = _safe_import("payloads.games.game_frogger")
        assert mod is not None

    def test_has_play(self):
        mod = _safe_import("payloads.games.game_frogger")
        assert hasattr(mod, "play") or hasattr(mod, "main")

    def test_has_pins(self):
        mod = _safe_import("payloads.games.game_frogger")
        assert isinstance(mod.PINS, dict)


# =========================================================================
# game_asteroids.py
# =========================================================================
class TestGameAsteroids:
    def test_import_smoke(self):
        mod = _safe_import("payloads.games.game_asteroids")
        assert mod is not None

    def test_wrap(self):
        mod = _safe_import("payloads.games.game_asteroids")
        x, y = mod.wrap(-10, 200)
        assert 0 <= x <= mod.WIDTH
        assert 0 <= y <= mod.HEIGHT

    def test_new_ship(self):
        mod = _safe_import("payloads.games.game_asteroids")
        ship = mod.new_ship()
        assert "x" in ship
        assert "y" in ship
        assert "angle" in ship

    def test_score_for_radius(self):
        mod = _safe_import("payloads.games.game_asteroids")
        # Smaller asteroids should score more
        big = mod.score_for_radius(20)
        small = mod.score_for_radius(8)
        assert small >= big

    def test_make_asteroid_shape(self):
        mod = _safe_import("payloads.games.game_asteroids")
        shape = mod.make_asteroid_shape(15)
        assert isinstance(shape, list)
        assert len(shape) > 0


# =========================================================================
# game_sokoban.py
# =========================================================================
class TestGameSokoban:
    def test_import_smoke(self):
        mod = _safe_import("payloads.games.game_sokoban")
        assert mod is not None

    def test_has_levels(self):
        mod = _safe_import("payloads.games.game_sokoban")
        assert hasattr(mod, "RAW_LEVELS") or hasattr(mod, "LEVELS")
        levels = getattr(mod, "RAW_LEVELS", None) or getattr(mod, "LEVELS", [])
        assert len(levels) >= 10

    def test_has_parse_level(self):
        mod = _safe_import("payloads.games.game_sokoban")
        assert hasattr(mod, "parse_level")

    def test_has_pins(self):
        mod = _safe_import("payloads.games.game_sokoban")
        assert isinstance(mod.PINS, dict)

    def test_make_state(self):
        mod = _safe_import("payloads.games.game_sokoban")
        st = mod.make_state({(1, 1)}, (0, 0), 5)
        assert st["moves"] == 5
        assert st["player"] == (0, 0)

    def test_push_pop_history(self):
        mod = _safe_import("payloads.games.game_sokoban")
        h = []
        st1 = mod.make_state({(1, 1)}, (0, 0), 0)
        st2 = mod.make_state({(2, 2)}, (1, 1), 1)
        h = mod.push_history(h, st1)
        h = mod.push_history(h, st2)
        assert len(h) == 2
        h2, popped = mod.pop_history(h)
        assert len(h2) == 1


# =========================================================================
# game_connect4.py
# =========================================================================
class TestGameConnect4:
    def test_import_smoke(self):
        mod = _safe_import("payloads.games.game_connect4")
        assert mod is not None

    def test_empty_board(self):
        mod = _safe_import("payloads.games.game_connect4")
        board = mod.empty_board()
        assert len(board) == mod.ROWS
        assert len(board[0]) == mod.COLS
        assert all(board[r][c] == mod.EMPTY for r in range(mod.ROWS) for c in range(mod.COLS))

    def test_drop_piece(self):
        mod = _safe_import("payloads.games.game_connect4")
        board = mod.empty_board()
        new_board, row = mod.drop_piece(board, 3, mod.PLAYER)
        assert new_board is not None
        assert row == mod.ROWS - 1
        assert new_board[row][3] == mod.PLAYER

    def test_drop_piece_full_column(self):
        mod = _safe_import("payloads.games.game_connect4")
        board = mod.empty_board()
        for _ in range(mod.ROWS):
            board, _ = mod.drop_piece(board, 0, mod.PLAYER)
        result, row = mod.drop_piece(board, 0, mod.PLAYER)
        assert result is None
        assert row == -1

    def test_valid_columns(self):
        mod = _safe_import("payloads.games.game_connect4")
        board = mod.empty_board()
        cols = mod.valid_columns(board)
        assert len(cols) == mod.COLS

    def test_check_win_no_winner(self):
        mod = _safe_import("payloads.games.game_connect4")
        board = mod.empty_board()
        assert mod.check_win(board, mod.PLAYER) == []

    def test_check_win_horizontal(self):
        mod = _safe_import("payloads.games.game_connect4")
        board = mod.empty_board()
        # Place 4 in a row at bottom
        for c in range(4):
            board, _ = mod.drop_piece(board, c, mod.PLAYER)
        result = mod.check_win(board, mod.PLAYER)
        assert len(result) == 4

    def test_is_draw_empty(self):
        mod = _safe_import("payloads.games.game_connect4")
        board = mod.empty_board()
        assert mod.is_draw(board) is False

    def test_evaluate_window(self):
        mod = _safe_import("payloads.games.game_connect4")
        score = mod.evaluate_window(
            [mod.PLAYER, mod.PLAYER, mod.PLAYER, mod.EMPTY], mod.PLAYER
        )
        assert score > 0
