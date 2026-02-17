const C_RESET = "\u001b[0m", 
      C_RED = "\u001b[31m", 
      C_BRED = "\u001b[91m", 
      C_GREEN = "\u001b[32m", 
      C_BOLD = "\u001b[1m", 
      C_YELLOW = "\u001b[33m",
      C_CYAN = "\u001b[36m";

export const color = (c, t) => `${c}${t}${C_RESET}`;

export const COLORS = {
    RESET: C_RESET,
    RED: C_RED,
    BRED: C_BRED,
    GREEN: C_GREEN,
    BOLD: C_BOLD,
    YELLOW: C_YELLOW,
    CYAN: C_CYAN
};
