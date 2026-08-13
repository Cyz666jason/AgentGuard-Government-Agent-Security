(module
  (memory (export "memory") 1 2)
  (func (export "run") (param $limit i32) (result i32)
    local.get $limit
  )
)
