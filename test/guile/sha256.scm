#!/usr/bin/guile -s
!#
(load-extension "/usr/local/lib/libyacl" "yacl_init_guile")
(use-modules (rnrs bytevectors))
(define bv (make-bytevector 3))
(define (%numstr->bin str final base)
  (define len (string-length str))
  (let lp((i 0) (ret '()))
    (cond
     ((= i len) (final (reverse! ret)))
     (else (lp (+ i 2) (cons (string->number (substring str i (+ i 2)) base) ret))))))

(define (hex->bin str)
  (%numstr->bin str u8-list->bytevector 16))

(define (hex->list str)
  (%numstr->bin str identity 16))

(define (hex->ascii str)
  (%numstr->bin str (lambda (x) (utf8->string (u8-list->bytevector x))) 16))

(define bv (hex->bin "616263"))

(begin (display (yacl-sha256 bv))
       (newline))
