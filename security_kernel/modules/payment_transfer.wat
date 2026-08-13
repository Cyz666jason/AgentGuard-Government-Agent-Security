(module
  (memory (export "memory") 1 2)
  (func (export "run") (param $amount i32) (result i32)
    local.get $amount
  )
)
