(define-module (cryptotronix hex)
  #:version (0 2)
  #:use-module (rnrs bytevectors)
  #:use-module (srfi srfi-1)
  #:use-module (ice-9 format)
  #:use-module (srfi srfi-64)
  #:use-module (srfi srfi-9)
  #:use-module (srfi srfi-9 gnu)
  #:use-module (srfi srfi-11)
  #:export (hex->bin
            hex->list
            hex->ascii
            hex-string->bytevector
            hex-string->list
            bytevector->hex-string
            ))

(load-extension "/usr/local/lib/libyacl" "yacl_init_guile")

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

;; From https://raw.githubusercontent.com/artyom-poptsov/guile-ssh/master/ssh/key.scm
(define (bytevector->hex-string bv)
  "Convert bytevector BV to a colon separated hex string."
  (string-join (map (lambda (e) (format #f "~2,'0x" e))
                    (bytevector->u8-list bv))
               ":"))

(define (yacl-trim str) (string-filter char-set:letter+digit str))

(define (hex-string->bytevector hex)
  (hex->bin (trim hex)))

(define (hex-string->list lst)
  (hex->list (trim lst)))
