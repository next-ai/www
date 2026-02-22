from flask import Blueprint, render_template_string

tictactoe_bp = Blueprint("tictactoe", __name__, url_prefix="/tictactoe")

TICTACTOE_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Tic-Tac-Toe</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background: #f5f0eb; color: #2c2c2c;
    min-height: 100vh; display: flex;
    align-items: center; justify-content: center;
  }
  .container { max-width: 400px; width: 90%; text-align: center; }
  h1 { font-size: 1.8em; font-weight: 600; color: #3a3a3a; margin-bottom: 6px; }
  .status {
    font-size: 1em; color: #9a8f85; margin-bottom: 20px;
    min-height: 1.4em; transition: color 0.2s;
  }
  .status.win { color: #5a9a6a; font-weight: 600; }
  .status.lose { color: #c45; font-weight: 600; }
  .status.draw { color: #b08d57; font-weight: 600; }
  .board {
    display: grid; grid-template-columns: repeat(3, 1fr);
    gap: 8px; margin: 0 auto 24px; max-width: 300px;
  }
  .cell {
    aspect-ratio: 1; background: #fff;
    border: 1px solid #e8e2dc; border-radius: 12px;
    font-size: 2.4em; font-weight: 600;
    cursor: pointer; display: flex;
    align-items: center; justify-content: center;
    transition: all 0.15s;
    box-shadow: 0 1px 3px rgba(0,0,0,0.04);
    color: #2c2c2c;
  }
  .cell:hover:not(.taken):not(.game-over) {
    border-color: #c9bfb4;
    box-shadow: 0 4px 16px rgba(0,0,0,0.07);
    transform: translateY(-2px);
  }
  .cell.taken, .cell.game-over { cursor: default; }
  .cell.x { color: #3a3a3a; }
  .cell.o { color: #9a8f85; }
  .cell.winner { background: #edf7f0; border-color: #5a9a6a; }
  .scores {
    display: flex; justify-content: center; gap: 24px;
    margin-bottom: 20px; font-size: 0.9em; color: #9a8f85;
  }
  .scores span { font-weight: 600; color: #3a3a3a; }
  .btn-row { display: flex; gap: 10px; justify-content: center; }
  .btn {
    font-family: inherit; font-weight: 500; font-size: 0.88em;
    padding: 10px 28px; border: 1px solid #e8e2dc;
    border-radius: 10px; cursor: pointer;
    color: #9a8f85; background: #fff;
    box-shadow: 0 1px 3px rgba(0,0,0,0.04);
    transition: all 0.2s; text-decoration: none;
    display: inline-block;
  }
  .btn:hover { color: #6b5f53; border-color: #c9bfb4; }
</style>
</head>
<body>
<div class="container">
  <h1>Tic-Tac-Toe</h1>
  <div class="status" id="status">Your turn (X)</div>
  <div class="scores">
    Wins: <span id="wins">0</span> &nbsp;
    Losses: <span id="losses">0</span> &nbsp;
    Draws: <span id="draws">0</span>
  </div>
  <div class="board" id="board"></div>
  <div class="btn-row">
    <a href="/" class="btn">Home</a>
    <button class="btn" onclick="restart()">Restart</button>
  </div>
</div>
<script>
const HUMAN = 'X', AI = 'O';
let board, gameOver, scores = { wins: 0, losses: 0, draws: 0 };

function init() {
  board = Array(9).fill(null);
  gameOver = false;
  const el = document.getElementById('board');
  el.innerHTML = '';
  for (let i = 0; i < 9; i++) {
    const cell = document.createElement('div');
    cell.className = 'cell';
    cell.dataset.idx = i;
    cell.addEventListener('click', () => humanMove(i));
    el.appendChild(cell);
  }
  setStatus("Your turn (X)", '');
}

function setStatus(msg, cls) {
  const el = document.getElementById('status');
  el.textContent = msg;
  el.className = 'status' + (cls ? ' ' + cls : '');
}

function updateScores() {
  document.getElementById('wins').textContent = scores.wins;
  document.getElementById('losses').textContent = scores.losses;
  document.getElementById('draws').textContent = scores.draws;
}

function render() {
  const cells = document.querySelectorAll('.cell');
  cells.forEach((cell, i) => {
    cell.textContent = board[i] || '';
    cell.classList.toggle('taken', !!board[i]);
    cell.classList.toggle('x', board[i] === 'X');
    cell.classList.toggle('o', board[i] === 'O');
    cell.classList.toggle('game-over', gameOver);
  });
}

function checkWin(b) {
  const lines = [
    [0,1,2],[3,4,5],[6,7,8],
    [0,3,6],[1,4,7],[2,5,8],
    [0,4,8],[2,4,6]
  ];
  for (const [a,c,d] of lines) {
    if (b[a] && b[a] === b[c] && b[a] === b[d]) return { winner: b[a], line: [a,c,d] };
  }
  return null;
}

function highlight(line) {
  const cells = document.querySelectorAll('.cell');
  line.forEach(i => cells[i].classList.add('winner'));
}

function humanMove(i) {
  if (gameOver || board[i]) return;
  board[i] = HUMAN;
  render();
  const result = checkWin(board);
  if (result) { endGame(result); return; }
  if (board.every(c => c)) { endGame(null); return; }
  setTimeout(aiMove, 200);
}

function aiMove() {
  const move = bestMove(board, AI);
  board[move] = AI;
  render();
  const result = checkWin(board);
  if (result) { endGame(result); return; }
  if (board.every(c => c)) { endGame(null); return; }
}

function endGame(result) {
  gameOver = true;
  render();
  if (!result) {
    scores.draws++;
    setStatus("It's a draw!", 'draw');
  } else {
    highlight(result.line);
    if (result.winner === HUMAN) {
      scores.wins++;
      setStatus('You win!', 'win');
    } else {
      scores.losses++;
      setStatus('AI wins!', 'lose');
    }
  }
  updateScores();
}

function minimax(b, player, depth) {
  const result = checkWin(b);
  if (result) return result.winner === AI ? 10 - depth : depth - 10;
  if (b.every(c => c)) return 0;
  const moves = [];
  for (let i = 0; i < 9; i++) {
    if (!b[i]) {
      b[i] = player;
      moves.push(minimax(b, player === AI ? HUMAN : AI, depth + 1));
      b[i] = null;
    }
  }
  return player === AI ? Math.max(...moves) : Math.min(...moves);
}

function bestMove(b, player) {
  let best = -Infinity, move = -1;
  for (let i = 0; i < 9; i++) {
    if (!b[i]) {
      b[i] = player;
      const score = minimax(b, HUMAN, 0);
      b[i] = null;
      if (score > best) { best = score; move = i; }
    }
  }
  return move;
}

function restart() { init(); }
init();
</script>
</body>
</html>
"""


@tictactoe_bp.route("/")
def tictactoe():
    return render_template_string(TICTACTOE_TEMPLATE)
