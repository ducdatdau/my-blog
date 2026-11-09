---
title: "Một số bài toán Olympic Đại số"
date: 2026-11-08
categories: [Mathematics]
tags: [algebra]
math: true
published: false
---

## Bài tập

**Bài 1:** Cho $A, B \in M(n,R)$ thỏa mãn $rank(AB-BA) = 1$. Chứng minh rằng $(AB - BA)^2 = O_n$ với $O_n$ là ma trận vuông cấp $n$, chứa tất cả các hệ số bằng 0.

\begin{equation}
\left( \sum_{i=1}^{n} a_i b_i \right)^2 \leq \left( \sum_{i=1}^{n} a_i^2 \right) \left( \sum_{i=1}^{n} b_i^2 \right)
\label{eq:cauchy-schwarz}
\end{equation}

Dấu bằng xảy ra khi và chỉ khi $\dfrac{a_1}{b_1} = \dfrac{a_2}{b_2} = \cdots = \dfrac{a_n}{b_n}$.

## Chứng minh

Xét hàm bậc hai theo $t$:

\begin{equation}
f(t) = \sum_{i=1}^{n} (a_i t - b_i)^2 \geq 0, \quad \forall t \in \mathbb{R}
\label{eq:quadratic}
\end{equation}

Khai triển:

\begin{equation}
f(t) = \left(\sum a_i^2\right) t^2 - 2\left(\sum a_i b_i\right) t + \sum b_i^2 \geq 0
\label{eq:expand}
\end{equation}

Vì $f(t) \geq 0$ với mọi $t$, nên biệt thức $\Delta \leq 0$:

\begin{equation}
\Delta = 4\left(\sum a_i b_i\right)^2 - 4\left(\sum a_i^2\right)\left(\sum b_i^2\right) \leq 0
\label{eq:discriminant}
\end{equation}

Từ $\eqref{eq:discriminant}$, suy ra:

\begin{equation}
\left(\sum_{i=1}^{n} a_i b_i\right)^2 \leq \left(\sum_{i=1}^{n} a_i^2\right)\left(\sum_{i=1}^{n} b_i^2\right) \quad \blacksquare
\label{eq:result}
\end{equation}

## Ví dụ áp dụng

**Bài toán:** Cho $a, b, c > 0$ và $a + b + c = 3$. Chứng minh rằng:

\begin{equation}
a^2 + b^2 + c^2 \geq 3
\label{eq:example}
\end{equation}

**Lời giải:** Áp dụng Cauchy-Schwarz dạng Engel (Titu's Lemma), từ $\eqref{eq:cauchy-schwarz}$:

\begin{equation}
a^2 + b^2 + c^2 = \frac{a^2}{1} + \frac{b^2}{1} + \frac{c^2}{1} \geq \frac{(a+b+c)^2}{3} = \frac{9}{3} = 3
\label{eq:solution}
\end{equation}

Dấu bằng xảy ra khi $a = b = c = 1$.
