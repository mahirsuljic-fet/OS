#!/usr/bin/env -S dotnet fsi

module Console =

    open System

    let log =
        let lockObj = obj()
        fun color s ->
            lock lockObj (fun _ ->
                Console.ForegroundColor <- color
                printf "%s" s
                Console.ResetColor())

    let red = log ConsoleColor.Red
    let yellow = log ConsoleColor.Yellow
    let green = log ConsoleColor.Green
    let blue = log ConsoleColor.Blue
    let white = log ConsoleColor.White


let showVM (addr:uint32) =
  let dir_no = addr >>> 22
  let addr_without_dir = addr &&& 0x3fffffu
  let page_no = addr_without_dir >>> 12
  let byte_no = addr_without_dir &&& 0xfffu  

  Console.red <| sprintf "%10i" dir_no
  Console.yellow <| sprintf "%10i" page_no
  Console.green <| sprintf "%12i" byte_no
  printfn ""
 
  Console.red <| sprintf "%010B" dir_no
  Console.yellow <| sprintf "%010B" page_no
  Console.green <| sprintf "%012B" byte_no
  printfn ""

  Console.blue <| sprintf "%032B" addr
  Console.blue <| sprintf " = %i" addr
  printfn ""

if Array.length fsi.CommandLineArgs > 1 then
  let addrStr = fsi.CommandLineArgs[1]
  match System.UInt32.TryParse addrStr with
    | true,addr -> showVM(addr)
    | _ -> printfn "Prevelik ili loše formatiran broj"

else
  printfn "Pozovite program sa adresom u virtuelnoj memoriji!"
