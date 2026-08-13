(module
  (func (export "run") (result i32)
    (loop $forever
      i32.const 1
      drop
      br $forever
    )
    i32.const 0
  )
)
