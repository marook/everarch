;; -*- lexical-binding: t -*-
;;
;; templar.el is a templating library for emacs.
;; Copyright (C) 2022 Markus Peröbner
;;
;; This program is free software: you can redistribute it and/or modify
;; it under the terms of the GNU Affero General Public License as published by
;; the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.
;;
;; This program is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU Affero General Public License for more details.
;;
;; You should have received a copy of the GNU Affero General Public License
;; along with this program.  If not, see <https://www.gnu.org/licenses/>.

(ert-deftest templar-templar--render-string-template ()
  (seq-let
      (out-vars rendition)
      (templar--render '(("templar-offset" . 0)) "hello")
    (should (equal rendition "hello"))
    (should (equal (cdr (assoc-string "templar-offset" out-vars)) 5))))

(ert-deftest templar-templar--render-function-template-returns-nil ()
  (seq-let
      (out-vars rendition)
      (templar--render
       '(("templar-offset" . 0))
       (lambda (vars)
         nil))
    (should (equal rendition ""))))

(ert-deftest templar-templar--render-function-template-returns-vars-body ()
  (seq-let
      (out-vars rendition)
      (templar--render
       '(("templar-offset" . 1))
       (lambda (vars)
         (should (equal (cdr (assoc-string "templar-offset" vars)) 1))
         (list '(("templar-offset" . 1) ("my-var" . 2)) "peng")))
    (should (equal rendition "peng"))
    (should (equal (cdr (assoc-string "my-var" out-vars)) 2))))

(ert-deftest templar-templar--render-nested-template ()
  (seq-let
      (out-vars rendition)
      (templar--render
       '(("templar-offset" . 0))
       '("peng"))
    (should (equal rendition "peng"))
    (should (equal (cdr (assoc-string "templar-offset" out-vars)) 4))))
